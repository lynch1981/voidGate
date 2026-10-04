# Design: logban, access-log bans for costly URLs

Read nginx's access log, find clients that spend nearly all their requests
on expensive endpoints, and push them down to XDP as timed drops. A
second decider for the [Layer 7 bridge](l7-bridge.md), next to
`resty.voidgate`. It needs no Lua and works with plain nginx.

Contents:

1. [Problem](#1-problem)
2. [Scope](#2-scope)
3. [Architecture](#3-architecture)
4. [Input](#4-input)
5. [Scoring](#5-scoring)
6. [Exemptions](#6-exemptions)
7. [Bans](#7-bans)
8. [Behind a CDN](#8-behind-a-cdn)
9. [`cdn_allow.py`](#9-cdn_allowpy)
10. [Output](#10-output)
11. [Performance](#11-performance)
12. [Security](#12-security)
13. [Failure modes](#13-failure-modes)
14. [Alternatives considered](#14-alternatives-considered)
15. [Limits and future work](#15-limits-and-future-work)
16. [Tests](#16-tests)

## 1. Problem

A CC attack (an application-layer flood) does not fill the NIC. A few
hundred clients each loop on one expensive URL, such as a search, a
report or a login, and exhaust the backend at a packet rate voidGate's
flood policy never notices.

The access log already shows the attack. The attacking addresses are near
the top of the request counts for the costly URL, and almost none of
their requests go anywhere else. A browser that searches also loads
pages, CSS, JS and images. A bot that floods `/search` loads nothing else.

**Goal:** turn that observation into a per-address rule, apply it to the
live log, and drop the offenders at XDP for a while.

## 2. Scope

In scope:

- **nginx access logs**, in `combined` format optionally followed by the
  `rt=` and `urt=` timing fields. Kong and APISIX logs work when they use
  this format.
- **Per-address rules** over a sliding window, with timed drops through
  the existing `drop <ip> ttl=<sec>` (l7-bridge §4).
- **Watches**: per-address counts of requests by method, path and status
  (404 scans, failed logins, `limit_req` 429s), §5.7.
- **Fingerprint clusters**: many addresses, each under every threshold,
  sharing one JA4 and user agent and sending nearly only costly
  requests, §5.8.
- **Profiles** by path, user agent or JA4 TLS fingerprint, each with its
  own thresholds (§5.4, §5.5).
- **Replay**, to tune thresholds on old logs, **review**, to ban only
  what a person confirms, and **follow**, to enforce live.
- **A CDN in front:** its edges are never banned (§8).

Out of scope:

- **No change to the daemon or BPF.** logban is a socket client, like
  `voidgatectl`.
- **No WAF.** No signatures, no request bodies, no challenge pages.
- **No banning of clients behind a CDN.** XDP cannot see them (§8).
- **No distributed detection.** One log, one VM.
- **No persistence.** Offense counts start over on restart (§15).

The bridge's rules still hold: timed drops expire by themselves, are
never aggregated into a `/24` or `/64`, and `local_*` / `allow_*` are
refused.

## 3. Architecture

```
 nginx ──writes──▶ access.log
                       │ tail -F (or replay: files, .gz, stdin)
 ┌─────────────────────▼──────────────────────────────────────────┐
 │ logban.py                                                      │
 │                                                                │
 │  parse_line ──▶ honey path? ──yes──▶ exempt? ──no──▶ ban now   │
 │                     │ no                          (§5.6)       │
 │                     ▼                                          │
 │                 skip path? ──▶ path report (--top-paths)       │
 │                     │                                          │
 │                     ▼                                          │
 │           allowlisted address? ──yes──▶ not judged (§6.1)      │
 │                     │ no                                       │
 │                     ▼                                          │
 │  profile: path / ua / ja4 (§5.4)                               │
 │  Window: per (address, profile) [total, costly, backend s]     │
 │  and per (address, watch) [hits] (§5.7)                        │
 │  and per (ja4, ua, address) [total, costly] (§5.8)             │
 │                     │ every step (10 s, over 60 s)             │
 │                     ▼                                          │
 │  Judge: ratio | backend | watch | cluster ──▶ crawler? (§6.3)  │
 │                     │                                          │
 │                     ▼                                          │
 │  ban: ttl × 2^offense ──▶ stdout line ──▶ socket (unless -n)   │
 └─────────────────────────────────────────────────┬──────────────┘
                                                   │ drop <ip> ttl=N
                                    ┌──────────────▼───────────────┐
                                    │ voidgate: timed drop (reason │
                                    │ 4) → drop LPM → XDP_DROP     │
                                    └──────────────────────────────┘

 cron ──▶ cdn_allow.py ──▶ /etc/logban/cdn-allow.txt (allow_file, §9)
```

Files, all in `contrib/logban/`:

| File | Role |
|---|---|
| `logban.py` | the decider; one file, Python 3.8+, standard library only |
| `logban.conf` | example config, every key documented |
| `cdn_allow.py` | fetches a CDN's egress ranges into an `allow_file` |
| `test_logban.py` | unit tests for both scripts; no root, no daemon |
| `README.md` | how to run it |

## 4. Input

### 4.1 Log format

The `combined` format works as is. Two fields appended to it let logban
find costly paths by itself:

```nginx
log_format logban '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" rt=$request_time '
                  'urt=$upstream_response_time';
```

With a JA4 module (FoxIO's `ja4-nginx-module`; take the variable name
from its README), append the fingerprint too:

```nginx
                  'urt=$upstream_response_time ja4=$http_ssl_ja4';
```

| Field | Used for |
|---|---|
| first word | the address that is judged and banned. It **must be the TCP peer** (§8). |
| `$time_local` | window time, timezone included, so replays are exact |
| `$request` | the method and the path, without its query string; a malformed request line gives an empty method and path, still counted |
| `$status` | watches (§5.7) |
| `$http_user_agent` | profile matching only (§5.4); never trusted to exempt |
| `urt=` | backend seconds: the sum of every upstream tried (`0.5, 0.2 : 0.1`) |
| `rt=` | used when `urt` is `-` (nginx answered itself) |
| `ja4=` | profile matching and `--top-ja4` (§5.5); `-` or missing reads as none. `ja4t=` (the TCP fingerprint) is ignored. |

Lines that do not parse are counted and skipped.

### 4.2 JSON

A line that starts with `{` is read as JSON, as `log_format ...
escape=json` writes it; any other line as `combined`, so a file may mix
both (a format change mid-file, or two vhosts). No config is needed when
the fields carry nginx's variable names:

```nginx
log_format logban_json escape=json '{"time_local":"$time_local",'
    '"remote_addr":"$remote_addr","request":"$request","status":$status,'
    '"http_user_agent":"$http_user_agent","request_time":$request_time,'
    '"upstream_response_time":"$upstream_response_time",'
    '"ja4":"$http_ssl_ja4"}';
```

| Value | Fields tried, first present wins | Key to change it |
|---|---|---|
| address | `remote_addr` | `json_ip` |
| time | `time_local`, `time_iso8601`, `msec` | `json_time` |
| request | `request`; else `request_method` + `request_uri` or `uri` | `json_request`, `json_method`, `json_uri` |
| status | `status` | `json_status` |
| user agent | `http_user_agent` | `json_ua` |
| backend seconds | `upstream_response_time`, else `request_time` | `json_urt`, `json_rt` |
| JA4 | `ja4`, `http_ssl_ja4` | `json_ja4` |

Each key takes one field name or several, comma-separated, tried in
order: behind realip, `json_ip = realip_remote_addr` (§8). Values may be
strings or numbers; `-` and empty count as absent, as in `combined`. A
line that is not valid JSON, or lacks an address or a time, is
unparsed. A syslog prefix before the `{` is not stripped.

A line parsed from JSON is the same tuple as from `combined`: tests check
both give the same bans, and the sample `data/clickHouse.access.log`
(14,743 lines) gives identical reports read as JSON or converted.

### 4.3 Reading

- **Replay:** one or more files, read in order. `.gz` and `-` (stdin)
  work. The clock is the log's time, so an hour of log replays in seconds
  and gives the same verdicts each run.
- **Follow (`-f`):** like `tail -F`. Starts at the end of the file unless
  `--from-start` is given, buffers a partial last line, and reopens the
  file when its inode changes (rotation by rename) or it shrinks
  (`copytruncate`). While the log is quiet, the window moves on
  wall-clock time, so a client is still judged when its traffic stops.

## 5. Scoring

### 5.1 Window

Per address, a running `[total, costly, backend seconds]` over the last
`window` seconds, kept as `window / step` buckets:

- each line adds to the newest bucket and to the running totals;
- at each step boundary the window is **judged**, then the oldest
  bucket is subtracted and dropped;
- a line stamped before the current bucket counts in the current
  bucket. nginx logs a request when it ends, so lines arrive slightly out
  of order;
- a gap longer than the window (a quiet night, a replay of two days)
  judges once, then starts empty;
- end of input judges the last, partial window.

A sliding window, not a fixed one: an attack that straddles a boundary of
a fixed 60 s window would be split in two and could pass both halves.

### 5.2 Costly requests

A request is costly when either:

- its path matches a `costly` regex (`^/search`, `\.php$`, ...), or
- its backend time is at least `slow_seconds` (0 = off).

Backend time follows the site: an endpoint that becomes slow becomes
costly without a config change. Regexes pin the endpoints known to be
expensive even when they answer fast. Run `--top-paths N` on a real log
to see which paths cost the most backend time.

### 5.3 Rules

| Rule | Fires when (defaults) | Catches |
|---|---|---|
| `ratio` | `costly >= min_costly` (100) **and** `costly / total >= ratio` (0.9; `off` turns it off) | bots looping on costly URLs |
| `backend` | backend seconds `>= max_backend_seconds` (0 = off) | a client heavy on the backend whatever it requests |
| `honey` | one request to a `honey` path (§5.6) | scanners probing for `.env`, `.git`, admin panels |
| a watch's name | `<name>.max` requests matching the watch, and optionally `<name>.ratio` of the address's requests (§5.7) | path scans, failed logins, clients nginx is already throttling |
| `cluster` | its fingerprint cluster fires, and it behaves like the cluster (§5.8) | wide, slow botnets: each address under every threshold |

`min_costly` stops a short browsing burst from tripping the ratio. The
ratio is what lets CGNAT and office addresses pass: many users behind
one address send many costly requests, but also many cheap ones.

`max_backend_seconds` reads best as workers: backend seconds in one
window divided by the window is how many backend workers the client keeps
busy on average. `30` in a 60 s window is half a worker. Choose it from
`--top-clients` (§10) on a normal week of logs, not by guessing. A CGNAT
address carries many users' backend time, so it is the first legitimate
client this rule hits; in the synthetic log of §11 it peaks at 146 s,
ten times any single browser.

### 5.4 Profiles

Some clients cannot be judged by the ratio: an app or integration that
calls an API and nothing else has a ratio near 1.0 by design. A profile
gives a class of requests its own thresholds:

```
profile api = ua:^MyShop/        # or path:^/api/v1/; lines with one name OR
api.ratio = off
api.max_backend_seconds = 30     # half a worker per address
```

- **Chosen per request.** The first declared profile whose `path:`,
  `ua:` or `ja4:` regex matches; `default` (the global keys) when none
  does.
- **Counted apart.** The window is keyed by (address, profile). One NAT
  address with app users and browsers keeps two counters, so the app's
  costly calls do not push the browsers' ratio over the line.
- **Banned as one.** A rule firing in any profile bans the address, and
  clears all its counters. The rule is named after the profile:
  `rule=api.backend`.
- **Thresholds, not exemptions.** A user agent is free to forge. A bot
  that copies the app's gets the app's limits, and
  `api.max_backend_seconds` still bans it. That is why a profile cannot
  turn every rule off: a declared profile in which no rule can fire is a
  config error. `default` may judge nothing, if a profile does.
- Overridable: `min_costly`, `ratio`, `max_backend_seconds`. What is
  costly, the window and the ttl stay global.
- **NAT adds up.** A NAT address carrying 30 app users uses 30 users'
  backend time. In a synthetic test, one app install peaked at 4.8 s
  (p99.9), a NAT with ~30 of them at 31.4 s, and a bot forging the app's
  user agent at 379 s: `api.max_backend_seconds = 30` banned the NAT too,
  100 would separate them. Read `--top-clients` before choosing.

### 5.5 JA4

JA4 fingerprints the TLS ClientHello: version, cipher suites,
extensions, ALPN. It is a better signal than a user agent, because a
script has to change its TLS stack to fake it, not one header. A
profile matches it like any other field:

```
profile app = ja4:^t13d2014h2_a09f3c656075_14788d8d241b$     # iOS app
profile app = ja4:^t13d1516h2_8daaf6152771_02713d6af862$     # Android app
app.ratio = off
app.max_backend_seconds = 100

profile api_other = path:^/api/       # API calls from any other stack
api_other.min_costly = 20             # banned fast
```

An exact `ja4:^<fingerprint>$` goes into a set, so an allowlist of
dozens costs one lookup per line; any other `ja4:` is a regex.

**Thresholds, not an allowlist.** "Allow these fingerprints, block the
rest" fails real users:

| Property | Consequence |
|---|---|
| A fingerprint is a TLS stack, not an app | iOS `URLSession` is shared by Safari and every iOS app; OkHttp by every app on that version. Matching keeps out `python-requests`, Go's `net/http` and `curl`, not other apps. |
| OS and library updates change it | release day brings new fingerprints; a hard allowlist would block every updated user |
| Android fleets vary | dozens of fingerprints across OS versions and vendors |
| TLS-inspecting proxies and antivirus re-handshake | their users show the middlebox's fingerprint |
| It can be copied | `curl-impersonate`, `utls`, `curl_cffi` copy iOS or Chrome exactly |
| A CDN terminates TLS | the origin sees the CDN's handshake; take JA4 from the CDN, and check it there |

So a missing fingerprint moves its users to the stricter `api_other`,
which bans only those that also flood, and a copied fingerprint still
meets `app.max_backend_seconds`. Build the list from `--top-ja4` on
shadow logs (§10), not by hand, and run it again after each iOS or
Android release.

Synthetic test (82k lines: 300 app users, 500 browsers, two bots), with
the profiles above and `app.max_backend_seconds = 30`:

| Client | Profile | Result |
|---|---|---|
| a script sending the app's user agent from `python-requests` | `api_other` | banned after 20 costly calls |
| an impersonator with the iOS fingerprint, 0.8 s calls | `app` | banned, `rule=app.backend` |
| app users (peak 5.0 s), browsers | `app`, `default`, `api_other` | none banned |

Blocking unknown fingerprints at request time belongs in nginx, not in
logban or XDP: XDP would have to reassemble and parse TLS, and logban
only sees a request after it was served.

### 5.6 Honey paths

A path the site never serves and no page links to: `/.env`, `/.git`,
`/wp-login.php` on a site without WordPress. No real user asks for one,
and scanners ask for all of them, so one request is enough:

```
honey = ^/(wp-login\.php|xmlrpc\.php|\.env|\.git(/|$))
honey = ^/(phpmyadmin|pma|adminer)
honey_ttl = 3600
```

- **Banned at once.** On the line itself, stamped with its time, not at
  the next step. One ban per ttl however many probes follow.
- **Matched on the path**, without the query string, like `costly` and
  `skip`. Anchor with `^/`: `/blog/wp-login.php` is not a probe of the
  root. Write `\.git(/|$)`, not `\.git/`, or `/.git` itself is missed,
  and not `\.git`, or `/.github/...` is caught.
- **Before `skip`**, so a broad `skip` cannot hide a probe. Not counted
  in the window or the path report.
- **Exempt as usual:** `allow`, `allow_file` and verified crawlers. A
  CDN edge proxying a scanner is not banned (§8).
- **`honey_ttl`** (3600 s) starts the ttl, then doubles per offense like
  any ban, sharing the count with the other rules, up to `max_ttl`. The
  OpenResty example bans a day at once; logban starts lower because one
  infected phone behind a carrier's CGNAT address should not cut off
  everyone behind it for a day on its first probe.
- **Refused patterns.** A `honey` regex that matches `/` or an empty path
  (a malformed request line) would ban every client: config error.
- A ban that fails on the socket is not retried on a timer. Scanners
  send many probes, and the next one tries again. A refused one is held
  like any other (§7.2).

Do not list a path a real page links to, even a hidden link: browser
prefetching, accessibility tools and mail link scanners follow links. A
link meant as a trap must be `rel="nofollow"` and `Disallow`ed in
`robots.txt`, so well-behaved crawlers stay out. Let nginx answer 404 for
honey paths, so the app never serves them.

### 5.7 Watches

The status is the server's verdict on a request, and some verdicts in
bulk give a client away. A watch counts, per address over the window,
the requests that match all of its conditions, and bans at `max`:

```
watch scan = status:404                       # path scanning
scan.max = 50
scan.ratio = 0.5

watch login = method:POST path:^/login$ status:401|403
login.max = 20                                # credential stuffing
login.ttl = 3600

watch throttled = status:429                  # limit_req said no
throttled.max = 30
```

- **Conditions** are `method:`, `path:` and `status:` regexes, separated
  by spaces, all of which must match. `path` is searched, like `costly`;
  `method` and `status` must match whole, so `status:4..` is any 4xx and
  `status:40` matches nothing. Several lines with one name OR.
- **`<name>.max`** (required) hits in the window ban the address,
  `rule=<name> hits=N`. **`<name>.ttl`** starts its ttl (default `ttl`),
  doubled per offense as usual.
- **`<name>.ratio`** (optional) also requires the hits to be that share
  of all the address's requests in the window. A page with a few missing
  images makes every visit a few 404s, and a NAT address with hundreds
  of visitors reaches 50 of them; a scanner's requests are almost all
  misses. With `scan.ratio = 0.5`, the NAT passes and the scanner does
  not.
- **What is counted:** the same requests as the window. Honey paths are
  checked first, skipped paths and allowlisted addresses are not
  counted, and a verified crawler is not banned. Watches count apart
  from profiles: a profile's thresholds do not change a watch.
- Names follow profile names, must differ from them, and cannot be
  `default`, `ratio`, `backend` or `honey`.

Notes for the three examples:

| Watch | Note |
|---|---|
| `scan` | Fill `honey` first: it bans on one probe. `scan` catches the paths nobody listed. Keep the ratio: broken links are common. |
| `login` | Only works if the app answers a failed login with 401, 403 or 422. Many answer 200 with an error page, or 302 back to the form, the same as a success; then the log cannot tell, and the app must rate-limit itself. |
| `throttled` | `limit_req` answers **503** unless `limit_req_status 429;` is set; match what your config sends. The client is already refused by nginx; this moves it to XDP, so its requests stop costing a TLS handshake and a parse. |

A watch has no profile or JA4 condition: add one if a case needs it.

### 5.8 Fingerprint clusters

Every rule above is per address. A botnet of 300 addresses, each sending
12 searches a minute, stays under all of them: in a synthetic test,
none of the 300 was banned. What gives it away is that its members look
alike and do one thing: they share a TLS stack and user agent, and
nearly all of their requests are costly.

```
cluster_min_addresses = 10      # 0 (default) is off
cluster_min_costly = 300        # costly requests of the whole cluster
cluster_ratio = 0.9             # costly share, of the cluster and of a member
cluster_member_min = 3          # costly requests of one member
```

A **cluster** is every address sending one (JA4, user agent) pair, or
one user agent when the log has no `ja4=`. It **fires** when, in one
window, it has at least `cluster_min_addresses` addresses, at least
`cluster_min_costly` costly requests, and a costly share of at least
`cluster_ratio`. Then each **member** with at least `cluster_member_min`
costly requests and its own costly share of at least `cluster_ratio` is
banned, `rule=cluster cluster=<addresses> ja4=... ua="..."`.

Each condition keeps someone safe:

| Condition | Keeps safe |
|---|---|
| cluster costly share | browsers: thousands of real users share Chrome's fingerprint, but load pages and assets, so their cluster's share stays low, and the few among them who only searched are not banned for it |
| member costly share | a real user who happens to share the bots' fingerprint, but browses |
| `cluster_member_min` | an address that sent one or two requests on that fingerprint |
| `cluster_min_addresses` | a single client: per-address rules handle it |
| only profiles with `ratio` on | an app's users: all costly by design (§5.4), one fingerprint; they would form a cluster at once |

Allowlisted addresses are not counted, verified crawlers are not banned,
and `--explain` shows a row per cluster the address is in, with the
reason it was or was not banned.

The test above, with clusters on (126k lines: 1000 browsers on one
Chrome fingerprint, 200 app users, the botnet copying Chrome's user agent
but not its TLS stack, and one real user on the bots' stack):

| | Banned |
|---|---|
| botnet, 300 addresses | all, 290 within 40 s of the cluster crossing its threshold |
| browsers, app users, the real user (its share: 0.23) | none |

**Limits.** A botnet that copies a common browser's TLS stack too
(`curl-impersonate`) joins the real users' cluster, whose share is low,
and passes. Real users of an uncommon stack who only hit costly paths
look like a botnet; keep `ttl` short.

## 6. Exemptions

| Exemption | Checked | Matches |
|---|---|---|
| `allow` | every line (cached) | CIDRs; `127.0.0.0/8` and `::1` always |
| `allow_file` | every line (cached) | CIDR files, re-read when replaced |
| `skip` | every line | path regexes: those requests are not judged; a `honey` path is checked first |
| `crawler` | only when a rule fires | reverse DNS suffix, confirmed forward |

### 6.1 Allowlists are applied as lines are read

An allowlisted address can never be banned, so its lines skip the
window. A busy CDN edge then holds no window state and puts no
`skip ... allow` lines in the `-v` output on every step. The result of
the CIDR check is cached per address (65,536 entries, then cleared), so
the cost per line is one dict lookup, not a scan of the list. Allowlisted
traffic still counts in `--top-paths`: behind a CDN, most real traffic is
there. An address that does not parse (`-`, a unix socket) is treated
the same way.

### 6.2 `allow_file`

One CIDR per line, `#` comments, repeatable key.

- **At startup**, a missing or broken file is a config error naming the
  file and line.
- **While running**, the files' inode, mtime and size are checked every
  step. A change re-reads them all, clears the per-address cache, and
  logs `allow_file reloaded: N networks`.
- **A broken update** keeps the old networks, logs
  `allow_file not reloaded`, and is not retried until the file changes
  again.
- An address that becomes allowlisted mid-window is not banned on the
  counts it already has: the check runs again when a rule fires.

### 6.3 Crawlers

A user agent is free to forge, so it is never trusted. A client is a
crawler when its reverse DNS name ends in a `crawler` domain
(`googlebot.com`, `search.msn.com`, ...) **and** that name resolves back
to the same address. This is what the search engines document. DNS is
slow, so it runs only for an address that already matched a rule, and
the result is cached.

### 6.4 Skipped paths

`skip` paths are left out of the window and of the path report: nothing
sent to them can get anyone banned, a flood included. For clients whose
ratio is near 1.0 by design, use a profile (§5.4) instead. Keep `skip`
for health checks and the like, and rate-limit them in nginx.

## 7. Bans

### 7.1 TTL

```
ttl = min(ttl × 2^(offenses), max_ttl)          defaults: 600 s, 86400 s
```

`offenses` counts earlier bans of the address. It resets to 0 once the
last ban is older than `offense_memory` (86400 s). TTLs are short
because one address may be a whole CGNAT: a wrong ban should end soon,
and a returning bot pays more each time.

### 7.2 After a ban

- The address's counts are removed from the window, so an expired ban
  does not fire again on old traffic.
- It is not judged again until its ttl has passed. In a replay the bot's
  lines keep coming (nothing really dropped them), so expect a second ban
  with a doubled ttl. Live, its packets are dropped at XDP and it
  disappears from the log.
- A ban that fails is printed with `error=` and is **not** counted as an
  offense. What happens next depends on who failed:

  | Failure | Next |
  |---|---|
  | the socket: daemon down, restarting, or it closed without a reply | retried at every step while the rule still fires |
  | the daemon replied `error: ...`: a protected address (`local_*`, `allow_*`), a full drop list, a failed map write | **held** for its ttl, like a ban: the line ends `retry_after=<ttl>s`, and the address is not judged again until then |

  The daemon gives one reply for all three refusals, so logban cannot
  tell a protected address from a full list. Holding is right for both:
  the same request would get the same answer at the next step, and a
  protected address would otherwise be refused, and logged by both
  sides, every 10 s for as long as it sends.

### 7.3 Review

`--review` (`-r`) replays the logs as a dry run, then shows one row per
address that would have been banned and asks which ones to ban:

```
  #  address       bans     ttl  costly  ratio   backend  rule          seen (UTC)
  1  2001:db8::e      2    1200     315   0.98    378.2s  ratio         10-03 10:47 .. 10:57
  2  203.0.113.3      2    1200     310   0.99    372.1s  ratio         10-03 10:07 .. 10:17
ban which? [a]ll, [n]one, or numbers like 1-3,7: 1
ban 2001:db8::e ttl=1200
```

- Rows are sorted by costly requests, most first. `bans`, `costly`,
  `backend` and `seen` add up every time the replay banned the address.
  `ttl` is the replay's last one, doubled for each repeat (§7.1).
- The answer is `a`, `n` (or Enter), or row numbers and ranges. Anything
  else asks again. End of input or Ctrl-C bans nothing.
- The prompt reads `/dev/tty`, not stdin, so logs can be piped in. With
  no terminal, `--review` exits 1.
- The picked addresses are banned when you answer, for their full ttl
  from that moment. With `-n`, they are only printed as `would ban`.
- Exit 1 if any picked ban failed.
- Not with `-f`: a prompt would stop the reading loop. For live
  enforcement, tune with `-r` first, then run `-f`.

### 7.4 In the daemon

logban's drops are ordinary timed drops (reason 4), so l7-bridge §5 applies
as is:

- a re-ban only extends: `expires = max(old, now + ttl)`;
- a manual drop of the same address wins and is never shortened;
- timed drops never count toward `aggregate_k`;
- any live drop keeps the gate ACTIVE (l7-bridge §8).

### 7.5 Explain

`--explain IP` (`-x`) answers "why was this address banned", or "why
not", from the logs: a replay as a dry run (nothing is sent, whatever
the config's socket) that prints only that address.

```
explain 203.0.113.1: 60 s window, judged every 10 s; times are window ends, UTC
2026-10-03 10:00:10  default      total=38 costly=37 backend=44.4s  under: costly 37 < min_costly 100
2026-10-03 10:00:20  default      total=94 costly=93 backend=111.6s  under: costly 93 < min_costly 100
2026-10-03 10:00:30  default      total=150 costly=149 backend=178.8s  fires ratio
2026-10-03 10:00:30  BAN          rule=ratio ttl=600 offense=1, until 2026-10-03 10:10:30
2026-10-03 10:10:20  banned       59 steps not shown: the replay keeps its requests, XDP would drop them
2026-10-03 10:10:30  default      total=133 costly=129 backend=154.9s  fires ratio
2026-10-03 10:10:30  BAN          rule=ratio ttl=1200 offense=2, until 2026-10-03 10:30:30

summary: 2976 lines: judged default 2976; skipped 0; honey 0
peak window, default: total 150, costly 149, backend 178.8 s
bans: ratio at 2026-10-03 10:00:30, ttl 600, ratio at 2026-10-03 10:10:30, ttl 1200
```

- **One row per judgment step** in which the address has requests in
  the window: per profile its counts and verdict, then per watch its
  hits, then per fingerprint cluster its size, costly share and the
  address's own. A verdict is `fires <rule>`, `fires <rule>, exempt: <why>`, or
  `under:` with the thresholds it missed (`costly 37 < min_costly 100`,
  `costly share 0.83 < ratio 0.90`, `backend 12.0 s < 30.0 s`, `hits 40 <
  max 50`, `hits share 0.10 < ratio 0.50`).
- **Honey hits and bans** get rows of their own; the steps judged while
  banned are folded into one `banned` row (§7.2).
- **Never judged:** an allowlisted address gets one row saying so, and
  the summary repeats it.
- **The summary**: lines judged per profile, skipped and honey lines,
  peak window per profile (outside bans), and every ban.
- **Not in the log**: says so, with the two usual causes. The argument is
  normalized (`2001:DB8:0::BAD` finds `2001:db8::bad`), but nginx logs an
  IPv4 client of an `[::]` listener without `ipv6only` as
  `::ffff:a.b.c.d`.

The verdicts use the same rule tests as the judge (`Profile.rule`,
`Watch.fires`), and a test checks that `--explain` reports the same bans
as a normal run. With no `--explain`, it costs nothing.

## 8. Behind a CDN

XDP sees the TCP peer, and the peer of a proxied request is the CDN's
edge. Hence:

| Traffic | Who can stop it |
|---|---|
| through the CDN | only the CDN: rate limiting, WAF, IP rules. Banning the edge at XDP would cut off every user behind it. |
| straight to the origin, bypassing the CDN | logban and voidGate. This is the usual attack once the origin address leaks. |

Setup:

1. **Log the peer.** With `real_ip_header`, `$remote_addr` is the
   client, which XDP never sees. Log `$realip_remote_addr` first, and the
   client in a field of its own for people to read:

   ```nginx
   set_real_ip_from 173.245.48.0/20;     # ... every CDN range
   real_ip_header   CF-Connecting-IP;
   log_format logban '$realip_remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent "$http_referer" '
                     '"$http_user_agent" rt=$request_time '
                     'urt=$upstream_response_time client=$remote_addr';
   ```

2. **Allowlist the CDN in logban** with `allow_file`, kept fresh by
   `cdn_allow.py` (§9).
3. **Allowlist it in voidGate too.** Add the same ranges to
   `allow_networks`, so the flood policy never drops the CDN and the
   daemon refuses a drop that slips through. The key replaces the
   built-in list (keep those entries) and holds at most 256 entries. The
   README prints the line.

## 9. `cdn_allow.py`

```
cdn_allow.py [-q] cloudflare /etc/logban/cdn-allow.txt
```

Fetches `https://api.cloudflare.com/client/v4/ips` and writes the ranges
one per line, under a header naming the source and the fetch time. It is
meant for cron, so it never makes the allowlist worse:

| Check | On failure |
|---|---|
| HTTP fetch succeeds (20 s timeout) | exit 1, file unchanged |
| JSON has `success: true` and both CIDR lists | exit 1, file unchanged |
| every entry is a valid CIDR string | exit 1, file unchanged |
| both IPv4 and IPv6 ranges present | exit 1, file unchanged |
| no prefix wider than `/8` (v4) or `/16` (v6) | exit 1, file unchanged |
| list is the same as the file's | exit 0, file **not rewritten**, so logban does not reload |

The new file is written next to the target, `fsync`ed, set to mode 0644
and renamed over it. A reader never sees half a file, and a crash leaves
the old one. Another CDN is one parser function and one entry in
`PROVIDERS`.

## 10. Output

stdout, one line per ban:

```
2026-10-03T10:00:30Z ban 203.0.113.1 ttl=600 offense=1 total=150 costly=149 ratio=0.99 backend=178.8s rule=ratio
```

The time is the end of the judged window, from the log's clock; for
`rule=honey`, the probe's own time, followed by `path=<the probe>`. A
failed ban adds `error="..."`, quoting the daemon's reply or the socket
error, and a refusal then `retry_after=<ttl>s` (§7.2):

```
2026-10-03T10:00:20Z ban 198.51.100.10 ttl=600 ... rule=ratio error="error: refused or map update failed" retry_after=600s
```

stderr:

| Line | When |
|---|---|
| `allow_file reloaded: N networks` | an `allow_file` changed |
| `allow_file not reloaded, keeping N networks: ...` | the change did not parse |
| `skip <ip> crawler\|allow total=N costly=N` | with `-v`, a verified crawler, or an address allowlisted mid-window (§6.2), matched a rule |
| `skip <ip> allow\|crawler honey <path>` | with `-v`, an exempt client hit a honey path |
| `N lines, N unparsed, N allowed, N honey hits` | at the end of a replay, with `-v` or a `--top-*` report |

`--review` prints its table and results on stdout instead of ban lines
(§7.3).

`--top-paths N` then prints the N paths with the most backend seconds,
or the most requests when the log has no timing fields.

`--top-clients N` prints the N (client, profile) pairs with the highest
**peak** backend seconds in one window, with that peak as workers, its requests and costly
requests, all their requests in the log, and whether this run banned
them. Then percentiles of the peaks over the clients that were not
banned, per profile, which is what to choose that profile's
`max_backend_seconds` from:

```
  #  address       profile  backend_s  workers requests   costly   all_req  banned
  1  203.0.113.6   default      406.9     6.78      344      339      2979  yes
 16  100.64.0.1    default      146.0     2.43      694      112     35982
 17  198.51.1.184  default       14.8     0.25       32       12        69

peak backend s per window, clients not banned:
  default    3001 clients  p50 6.4  p90 8.8  p99 11.2  p99.9 13.6  max 146.0
```

`--top-ja4 N` prints the N most used JA4 fingerprints: requests, share,
distinct addresses, addresses this run banned, backend seconds, and the
user agent each sends most. Then one profile line per fingerprint,
**commented out**: pasting them all would give whatever else is in the
log the app's limits, an attacker's script included.

```
  #  ja4                                   requests  share addresses banned  backend_s  top user agent
  1  t13d2014h2_a09f3c656075_14788d8d241b     41519  50.4%       201      1     4618.4  100% MyShop/5.2.1 (iOS 18.0)
  4  t13d1812h1_85036bcba153_b26ce05bbdd6       909   1.1%         1      0      272.7  100% MyShop/5.2.1 (iOS 18.0)

# Uncomment only your app's fingerprints; lines with one name OR.
# profile app = ja4:^t13d2014h2_a09f3c656075_14788d8d241b$    # 1 banned, MyShop/5.2.1 (iOS 18.0)
```

Read `addresses` with the user agent: row 4 claims to be the iOS app,
but its 909 requests come from one address, while the real iOS stack in
row 1 is spread over 201. Requests without a fingerprint show as
`(none)`.

Peaks are sampled at each judgment step. Allowlisted addresses are not
judged, so they are not listed. In a replay a banned client keeps
sending (§7.2), so its peak can be higher than at its ban. Without timing
fields both are by requests. Both reports are printed at the end of a
replay; a follow run does not end, so it prints neither.

## 11. Performance

One core, CPython 3.12, synthetic log of one hour: 339k lines from 3000
browsers, a CGNAT address and 15 bots.

| | |
|---|---|
| replay | 5.5 s, about 60k lines/s |
| parsing alone, a log with a new second on most lines (`data/`) | `combined` 83k lines/s, JSON 46k lines/s |
| bans | all 15 bots, each about 30 s into its attack; no browser, no CGNAT |
| allowlist filter (§6.1) | about 8 % of that time |
| one `ua:` profile (§5.4) | about 20 % more: a regex on every line |
| no watches | no cost |
| three watches (§5.7) | about 15 % more |
| clusters off | no cost |
| clusters on (§5.8) | about 18 % more |
| `--top-clients` | about 30 % more: peaks updated every step |
| a log without `ja4=` | no cost: the field is searched only when present |

A busy single VM logs far fewer lines per second. Past that rate, run it
under PyPy, or sample the log.

Memory grows with the number of distinct addresses in one window: one
small list per address per bucket. The per-address caches are cleared
past 65,536 entries, and the ban table drops expired bans past that size.
The offense counts are kept for every address ever banned (§15).

## 12. Security

- **Forged addresses.** A ban needs the TCP peer to have sent the
  requests, which takes a completed handshake, so a client cannot get a
  third party banned. The exception is a misconfiguration that logs a
  header-derived address (§8). Then the CDN allowlists in logban and
  voidGate are what stop a ban of the CDN.
- **Forged log fields.** nginx escapes `"` in logged variables as `\x22`,
  so a request or user agent cannot end its quoted field early and append
  a fake `rt=` or address.
- **Socket access.** Sending drops needs root or `ctl_socket_group`, and
  that grants the whole protocol (l7-bridge §11). Use `-n` while tuning.
- **Crawler spoofing.** User agents are ignored; only forward-confirmed
  reverse DNS exempts (§6.3).
- **User agent spoofing.** A user agent only picks a profile's
  thresholds, and every profile must be able to ban (§5.4).
- **JA4 spoofing.** Same rule: a copied fingerprint picks thresholds,
  never a pass (§5.5). `--top-ja4` prints its profile lines commented
  out, so an attacker's fingerprint is never allowlisted by a paste.
- **Honey paths and shared addresses.** One probe bans the address: a
  CGNAT address with one infected device in it is banned too, for
  `honey_ttl`. Keep it short, and never list a linked path (§5.6).
- **A poisoned CDN list** could turn logban off for large ranges.
  `cdn_allow.py` fetches over HTTPS and refuses anything wider than `/8`
  or `/16` (§9).

## 13. Failure modes

| Failure | Effect |
|---|---|
| daemon down, or socket not reachable | each ban printed with `error=`, retried every step until it succeeds |
| daemon refuses (address in `local_*` / `allow_*`, drop list full, map write failed) | printed once with `retry_after=`, held for the ttl, then judged again (§7.2) |
| honey ban fails | printed with `error=`; the scanner's next probe tries again |
| log rotated | follow reopens the new file; window and bans kept |
| log deleted | follow waits for it to reappear |
| `allow_file` missing or broken at startup | exit 1 with file and line |
| `allow_file` broken by an update | old networks kept, one warning |
| `cdn_allow.py` fetch or check fails | exit 1, old file kept |
| DNS down | crawler check fails closed: the client is banned like any other |
| logban crashes or restarts | live drops expire by themselves; offense counts and the window start over |
| nginx log buffering (`buffer=`, `flush=`) | bans later by the buffering delay |
| clock jump, or replay gap | one judgment, then an empty window |

## 14. Alternatives considered

- **GoAccess.** It reports top hosts and top paths separately, but not
  the paths of each host, which is the signal. Getting that means one run
  per candidate address. GoAccess stays useful as the dashboard people
  look at.
- **Detecting in OpenResty (`resty.voidgate.ban()`).** Faster, since it
  acts on the request itself, but it needs Lua and sees one request at a
  time. The two complement each other: logban needs no Lua and judges a
  client's whole mix of requests.
- **Two passes: top addresses on the costly URL, then each one's other
  URLs.** That computes the same thing as the ratio rule in one pass.
- **A fixed window.** Splits an attack at the boundary (§5.1).
- **Only a hand list of costly URLs.** It goes stale as the site changes;
  backend time does not. Both are supported.
- **Checking allowlists only when a rule fires.** That was the first
  version. Bans were the same, but busy CDN edges held window state and
  flooded `-v` output (§6.1).
- **Checking crawlers as lines are read.** That is a DNS lookup per new
  address.
- **Honey paths only in nginx** (the OpenResty example's `ban_now()`).
  Faster, at the request itself, but it needs Lua. logban gives plain
  nginx the same trap; with OpenResty, both can run.
- **fail2ban for the status cases.** Its nginx jails are regexes on the
  log with a count over a time window, which is what a watch is. A watch
  shares logban's window, allowlists, crawler check, refusal handling and
  offense count, and needs no second daemon; l7-bridge §14 has why
  fail2ban was not a decider.
- **Clusters by network prefix** (many bans in one /24). Botnets rent
  residential proxies spread over the internet, and CGNAT puts real
  users in one prefix; voidGate already refuses to aggregate timed
  drops for that reason (l7-bridge §5.4).
- **Clusters by user agent alone** when JA4 is logged. The user agent is
  one header a script sets to Chrome's; the TLS stack it rarely changes.
- **Separate rules per case** (`scan_404 = 50`, `login_fail = 20`).
  Every site's login path and failure status differ; one generic shape
  covers them, and the next case, without code.
- **A hit count for honey paths** (ban on the 3rd). A real user never
  sends even one, and scanners send dozens: one is enough.
- **A hard JA4 allowlist** (block every other fingerprint). Blocks
  users after an OS update, behind a TLS-inspecting proxy, or on an
  uncommon Android build, and copied fingerprints pass it (§5.5).
- **JA4 in XDP.** Means reassembling and parsing TLS from packets;
  voidGate only looks prefixes up.
- **Exempting API clients by user agent.** Their user agent is stable,
  but anyone can send it; it would be a free pass. Profiles use it to
  pick thresholds instead (§5.4).
- **One profile per address** (by its first request, or its most common
  user agent). A NAT address mixes apps and browsers; counting per
  (address, profile) keeps each mix honest.
- **Pricing requests by their path's typical time** instead of measured
  backend time. A slow, overloaded backend inflates every client's
  backend seconds during an attack. Not done yet (§15).
- **Fetching CDN ranges inside logban.** A network dependency in the ban
  loop, and a failure mode in every start. A separate cron job with
  atomic replace keeps logban offline.
- **A Python client library** (like `resty.voidgate`). Deferred: logban
  is its only Python user, and its socket code is one 30-line function.
  Worth it with a second Python decider, such as a CDN-API action.
- **awk.** Smaller, but sliding windows, ttl escalation, allowlist
  reloads and tests are awkward in it.

## 15. Limits and future work

Limits:

- **Slow, wide botnets that impersonate a browser.** Clusters (§5.8)
  catch a botnet with its own fingerprint. One that copies a common
  browser's TLS stack and user agent hides among real users; that needs
  a global signal: `limit_req` on the endpoint, or a challenge page.
- **Delay.** Up to one `step` after the threshold, plus log buffering.
- **Clients behind a CDN** cannot be banned at XDP (§8).

Future work:

- **A CDN-API action**, banning by real client address at the CDN
  (Cloudflare IP Access Rules), with the Python client library from §14.
- **More CDN providers** in `cdn_allow.py`.
- **Typical cost per path**, learned from quiet periods, so the backend
  rule does not tighten on everyone when the backend slows down.
- **Profiles by a hashed API key**, logged as a field and matched like
  `ja4:`, for APIs that issue keys.
- **Persisting offense counts** across restarts, and pruning them after
  `offense_memory` (today they live as long as the process).
- **A systemd unit** for follow mode.

## 16. Tests

`python3 contrib/logban/test_logban.py`, also run by `make test`. No root,
no daemon, about one second.

`sudo t/integration/logban.sh` runs logban against a real daemon in
private namespaces, about 10 s. Not part of `make test`, like the other
integration scripts.

| Test class | Covers |
|---|---|
| `ParseTest` | combined format, `urt` with several upstreams, `urt=-` falling back to `rt`, IPv6, timezones, garbage and malformed request lines |
| `JudgeTest` | bot banned, browser not; IPv6; `min_costly` and `ratio` boundaries; sliding window; `slow_seconds`; rule `backend`; `skip`; `allow`; forward-confirmed crawler versus a fake; one ban per ttl; ttl doubling and `max_ttl`; `offense_memory`; failed ban retried; a refusal held for its ttl, logged once, no offense, judged again after; late lines; `--top-paths` |
| `ConfigTest` | the example `logban.conf` loads; unknown keys, bad values and a config with nothing costly are errors |
| `AllowFileTest` | allowlisted addresses kept out of the window but in the path report, one allowlist check per address; missing or broken file at startup; reload on replace; broken update keeps the old list; counts made before the reload excused |
| `SocketTest` | the exact `drop <ip> ttl=N` sent; `ok`; a daemon's `error:` reply is a `Refused`; no reply and no daemon are not |
| `FollowTest` | follow across a rename rotation, counts kept |
| `TopClientsTest` | peak backend seconds, requests and all requests per client; workers column; percentiles over clients not banned; banned clients flagged; allowlisted clients absent; no timing falls back to requests; off unless asked |
| `ProfileTest` | profile keys inherit and override; config errors (field, regex, name, reserved `default`, undeclared, bounds, a profile that cannot fire, all rules off); first declared wins, `ua:` and `path:`, no user agent; an app passes with `api.ratio = off` but the same traffic is banned without the profile; a forged user agent still banned by `api.backend`; one NAT address counted apart; a ban clears every profile's counters; `--top-clients` per profile |
| `Ja4Test` | `ja4=` parsed, `-` / empty / missing as none, `ja4t=` ignored; exact fingerprints held as a set, other `ja4:` as regexes, exact means exact; known stacks pass while a script with the app's user agent and a plain-HTTP client are banned by `api_other`; a copied fingerprint banned by `app.backend`; `--top-ja4` columns, share, banned count, commented paste lines that load once uncommented; no `ja4=` in the log; off unless asked |
| `WatchTest` | method and status parsed, empty method for a malformed request; `scan` at `max` and below it; the window slides; `ratio` lets a NAT with missing images pass and bans a scanner; `login` counts POST 401 and 403, not GET, 200, 422 or another path; `throttled` on 429; OR lines and a status regex, `ttl`; allowlisted and skipped requests not counted; a verified crawler not banned; one ban clears every counter; a refusal held; config: values, watch-only and honey-only configs, errors (no or zero `max`, unknown field, empty condition, bad regex, reserved and bad names, undeclared, profile key on a watch and watch key on a profile, a name used for both, `ttl` and `ratio` bounds) |
| `HoneyTest` | first hit bans now with `honey_ttl`, `rule=honey path=`, kept out of the window and path report; anchored patterns hit `/.env`, `/.git`, `/.git/config` and miss `/.github`, a nested `wp-login.php`, a query string; one ban per ttl; escalation and `max_ttl`; offenses shared with the other rules; `allow`, loopback, verified crawler, bad address exempt; wins over `skip`; a failed ban retried by the next probe; shown in `--review`; config: refused patterns, `honey_ttl` bounds only with honey paths |
| `ExplainTest` | under, fires and BAN rows with their times, folded banned steps, summary; the same bans as a normal run; `under:` reasons (costly share, backend); allowlisted: never judged; verified crawler: exempt; honey, skipped, two profiles and a watch in one replay; watch ratio reason; not in the log; CLI: IPv6 normalized, the config's socket never used, bad address, refused with `-f` and `--review` |
| `ClusterTest` | a 30-address botnet each under every threshold: no ban by per-address rules, all banned by the cluster, ban line with size, ja4 and ua; user agent alone without `ja4=`; 50 browsers on one stack pass; search-only users inside a browser cluster pass; a member that browses and one with 2 costly requests pass; below `cluster_min_addresses`, below `cluster_min_costly`, spread over 10 minutes; ratio-off profiles not clustered; allowlisted not counted, verified crawlers not banned; off by default; `--explain` rows; config bounds only when on. Each of the three safety conditions was removed in turn and a test failed. |
| `JsonTest` | the same tuple as `combined` for the same request; `urt` with several upstreams, `-` falling back to `rt`, both absent; `ja4` from either name, `-` as none; `time_iso8601` with offsets and `msec` as string or number; `request_method` + `request_uri`; unparsed (cut short, no address, bad or wrong-typed time); `json_*` keys; the same bans in each format and mixed in one file; every line of the `data/` sample parses |
| `TimeTest` | the `time_local` fast path equals `strptime` (also checked on 20,000 random stamps and offsets while writing it); out-of-range and misshapen stamps rejected |
| `ReviewTest` | selection parsing (all, none, ranges, out of range, junk); table rows per address, most costly first, ttl doubled for a repeat; a bad answer asks again; end of input bans nothing; a failed ban exits 1; `-n` only prints; nothing to review; refused with `-f` |
| `CdnAllowTest` | Cloudflare JSON parsed and sorted; refused inputs (failure flag, a family missing, too wide, bad CIDR, wrong type, HTML); write, no rewrite when unchanged, failure keeps the file, no temp files left |

| `t/integration/logban.sh` | Covers |
|---|---|
| replay | ratio bans (IPv4 and IPv6), a honey ban (from a JSON line in the same file), a `scan` watch ban and a 12-address cluster land as `reason=4` drops; a browser is not dropped; a flood from the protected `local_networks` address is asked once (one logban line with `retry_after=600s`, one `refuse drop` line in the daemon log), not every step |
| follow | daemon stopped: a live flood's ban fails with `error=` and is retried every step; daemon started: the next retry lands the drop |

That XDP then drops the address is `t/drop-ttl-xdp.t`'s job: logban sends
the same `drop <ip> ttl=N` as `voidgatectl`. The test fails against the
logban before this fix: the protected address was asked 29 times.

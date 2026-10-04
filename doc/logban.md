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
 │  parse_line ──▶ skip path? ──▶ path report (--top-paths)       │
 │                     │                                          │
 │                     ▼                                          │
 │           allowlisted address? ──yes──▶ not judged (§6.1)      │
 │                     │ no                                       │
 │                     ▼                                          │
 │  Window: per address [total, costly, backend s], 60 s / 10 s   │
 │                     │ every step                               │
 │                     ▼                                          │
 │  Judge: rule ratio | rule backend ──▶ crawler? (DNS, §6.3)      │
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

| Field | Used for |
|---|---|
| first word | the address that is judged and banned. It **must be the TCP peer** (§8). |
| `$time_local` | window time, timezone included, so replays are exact |
| `$request` | the path, without its query string; a malformed request line gives an empty path, still counted |
| `$http_user_agent` | profile matching only (§5.4); never trusted to exempt |
| `urt=` | backend seconds: the sum of every upstream tried (`0.5, 0.2 : 0.1`) |
| `rt=` | used when `urt` is `-` (nginx answered itself) |

Lines that do not parse are counted and skipped.

### 4.2 Reading

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

- **Chosen per request.** The first declared profile whose `ua:` or
  `path:` regex matches; `default` (the global keys) when none does.
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

## 6. Exemptions

| Exemption | Checked | Matches |
|---|---|---|
| `allow` | every line (cached) | CIDRs; `127.0.0.0/8` and `::1` always |
| `allow_file` | every line (cached) | CIDR files, re-read when replaced |
| `skip` | every line | path regexes: those requests are not judged |
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
- A ban that fails (daemon down, refused) is printed with `error=`,
  is **not** counted as an offense, and is retried at the next step.

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

The time is the end of the judged window, from the log's clock. A failed
ban adds `error="..."`, quoting the daemon's reply or the socket error.

stderr:

| Line | When |
|---|---|
| `allow_file reloaded: N networks` | an `allow_file` changed |
| `allow_file not reloaded, keeping N networks: ...` | the change did not parse |
| `skip <ip> crawler\|allow total=N costly=N` | with `-v`, a verified crawler, or an address allowlisted mid-window (§6.2), matched a rule |
| `N lines, N unparsed, N allowed` | at the end of a replay, with `-v` or `--top-paths` |

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
| bans | all 15 bots, each about 30 s into its attack; no browser, no CGNAT |
| allowlist filter (§6.1) | about 8 % of that time |
| one `ua:` profile (§5.4) | about 20 % more: a regex on every line |
| `--top-clients` | about 30 % more: peaks updated every step |

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
- **A poisoned CDN list** could turn logban off for large ranges.
  `cdn_allow.py` fetches over HTTPS and refuses anything wider than `/8`
  or `/16` (§9).

## 13. Failure modes

| Failure | Effect |
|---|---|
| daemon down, or socket not reachable | each ban printed with `error=`, retried every step until it succeeds |
| daemon refuses (address in `local_*` / `allow_*`, drop list full) | same: retried every step (§15) |
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

- **Slow, wide botnets.** Many addresses each below `min_costly` per
  window pass. That needs a global signal: `limit_req` on the endpoint,
  or a challenge page.
- **Delay.** Up to one `step` after the threshold, plus log buffering.
- **Clients behind a CDN** cannot be banned at XDP (§8).

Future work:

- **Stop retrying a refusal.** A drop the daemon refuses
  (`local_*` / `allow_*`) will be refused at every step. Remember it for
  the ttl instead.
- **A CDN-API action**, banning by real client address at the CDN
  (Cloudflare IP Access Rules), with the Python client library from §14.
- **More CDN providers** in `cdn_allow.py`.
- **Typical cost per path**, learned from quiet periods, so the backend
  rule does not tighten on everyone when the backend slows down.
- **Profiles by a stronger identity**: a hashed API key or a JA4 TLS
  fingerprint logged as a field, matched like `ua:`.
- **Persisting offense counts** across restarts, and pruning them after
  `offense_memory` (today they live as long as the process).
- **A systemd unit** for follow mode.

## 16. Tests

`python3 contrib/logban/test_logban.py`, also run by `make test`. No root,
no daemon, about one second.

| Test class | Covers |
|---|---|
| `ParseTest` | combined format, `urt` with several upstreams, `urt=-` falling back to `rt`, IPv6, timezones, garbage and malformed request lines |
| `JudgeTest` | bot banned, browser not; IPv6; `min_costly` and `ratio` boundaries; sliding window; `slow_seconds`; rule `backend`; `skip`; `allow`; forward-confirmed crawler versus a fake; one ban per ttl; ttl doubling and `max_ttl`; `offense_memory`; failed ban retried; late lines; `--top-paths` |
| `ConfigTest` | the example `logban.conf` loads; unknown keys, bad values and a config with nothing costly are errors |
| `AllowFileTest` | allowlisted addresses kept out of the window but in the path report, one allowlist check per address; missing or broken file at startup; reload on replace; broken update keeps the old list; counts made before the reload excused |
| `SocketTest` | the exact `drop <ip> ttl=N` sent; `ok`, a refusal, no daemon |
| `FollowTest` | follow across a rename rotation, counts kept |
| `TopClientsTest` | peak backend seconds, requests and all requests per client; workers column; percentiles over clients not banned; banned clients flagged; allowlisted clients absent; no timing falls back to requests; off unless asked |
| `ProfileTest` | profile keys inherit and override; config errors (field, regex, name, reserved `default`, undeclared, bounds, a profile that cannot fire, all rules off); first declared wins, `ua:` and `path:`, no user agent; an app passes with `api.ratio = off` but the same traffic is banned without the profile; a forged user agent still banned by `api.backend`; one NAT address counted apart; a ban clears every profile's counters; `--top-clients` per profile |
| `ReviewTest` | selection parsing (all, none, ranges, out of range, junk); table rows per address, most costly first, ttl doubled for a repeat; a bad answer asks again; end of input bans nothing; a failed ban exits 1; `-n` only prints; nothing to review; refused with `-f` |
| `CdnAllowTest` | Cloudflare JSON parsed and sorted; refused inputs (failure flag, a family missing, too wide, bad CIDR, wrong type, HTML); write, no rewrite when unchanged, failure keeps the file, no temp files left |

Not covered: a real daemon. logban sends the same line that `voidgatectl
drop <ip> ttl=N` sends, which `t/drop-ttl.t` and `t/drop-ttl-xdp.t`
cover.

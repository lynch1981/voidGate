# logban: ban costly-URL abusers from the nginx access log

A prototype decider for voidGate's timed drops (`doc/l7-bridge.md`). It
reads the access log, finds clients that spend nearly all their requests
on expensive endpoints (a CC / application-layer flood), and pushes
`drop <ip> ttl=<sec>` to the control socket. It needs no Lua and works
with plain nginx. Python 3.8+, standard library only.

## The rule

Per client address, over a sliding `window` (60 s) judged every `step`
(10 s):

| rule | fires when |
|---|---|
| `ratio` | `costly >= min_costly` (100) **and** `costly / total >= ratio` (0.9) |
| `backend` | backend seconds used `>= max_backend_seconds` (off by default) |

A request is *costly* when its path matches a `costly` regex, or its
backend time is at least `slow_seconds`. Real browsers also fetch pages,
CSS, JS and images, so their ratio stays low even when they search a lot;
a bot looping on `/search` scores near 1.0.

A ban lasts `ttl` (600 s) and doubles for each repeat within
`offense_memory`, up to `max_ttl`. voidGate lifts it by itself.

## Log format

The default `combined` format works. Add backend time so logban can find
costly paths by itself and use `slow_seconds`:

```nginx
log_format logban '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" rt=$request_time '
                  'urt=$upstream_response_time';
access_log /var/log/nginx/access.log logban;
```

**The address must be the TCP peer.** XDP sees only the peer. With the
realip module on, `$remote_addr` is a client address XDP never sees: log
`$realip_remote_addr` instead. Behind a CDN, see the next section.

## Behind a CDN

A CDN's edge is the TCP peer for every request it proxies, so XDP can
only ever drop the CDN, never the client behind it. Allowlist the CDN's
egress ranges, and logban judges only clients that reach the origin
directly, usually an attacker that found the origin address and bypasses
the CDN. Clients that come through the CDN must be stopped at the CDN
(its rate limiting, WAF or IP rules).

Log the peer, not the real-IP header, so the allowlist matches:

```nginx
set_real_ip_from 173.245.48.0/20;     # ... every CDN range
real_ip_header   CF-Connecting-IP;
log_format logban '$realip_remote_addr - $remote_user [$time_local] '
                  '"$request" $status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" rt=$request_time '
                  'urt=$upstream_response_time client=$remote_addr';
```

Fetch the ranges into an `allow_file`, and refresh them from cron:

```sh
sudo mkdir -p /etc/logban
sudo python3 cdn_allow.py cloudflare /etc/logban/cdn-allow.txt
# /etc/cron.d/logban-cdn
17 4 * * *  root  python3 /path/to/cdn_allow.py -q cloudflare /etc/logban/cdn-allow.txt
```

```
# logban.conf
allow_file = /etc/logban/cdn-allow.txt
```

`cdn_allow.py` replaces the file only with a list that parsed, has both
IPv4 and IPv6 ranges and no prefix wider than `/8` or `/16`, and differs
from the current one. It writes a temporary file and renames it, so a
failed or partial fetch never empties the allowlist, and an unchanged
list does not touch the file. It exits 1 on failure, which cron mails.
logban notices the new file within one `step` and logs
`allow_file reloaded: N networks`.

Put the same ranges in voidGate's own `allow_networks`, so its flood
policy never drops the CDN either. The key replaces the built-in list,
so keep those too, and it holds at most 256 entries:

```sh
echo "allow_networks = 169.254.169.254/32, 127.0.0.0/8, ::1/128," \
     "fe80::/10, ff02::/16, $(grep -v '^#' /etc/logban/cdn-allow.txt |
     paste -sd, | sed 's/,/, /g')"
# paste the line into voidgate.conf, then: sudo voidgatectl reload
```

## Try it

```sh
# What costs the backend most? Use it to write the costly regexes.
python3 logban.py -n --top-paths 20 -c logban.conf /var/log/nginx/access.log

# Replay old logs (gzip works) and print what would have been banned.
python3 logban.py -n -c logban.conf /var/log/nginx/access.log.*.gz

# Live, dry: follow the log like tail -F.
python3 logban.py -n -f -c logban.conf /var/log/nginx/access.log

# Live, enforcing (root, or a member of ctl_socket_group).
sudo python3 logban.py -f -c logban.conf /var/log/nginx/access.log
```

One line per ban on stdout:

```
2026-10-03T10:00:30Z ban 203.0.113.1 ttl=600 offense=1 total=150 costly=149 ratio=0.99 backend=178.8s rule=ratio
```

A refused or failed drop adds `error="..."` and is retried at the next
step. `-v` also prints verified crawlers that matched a rule.

Addresses in `allow` or an `allow_file` are dropped from the analysis as
they are read (one cached lookup per address), so a busy CDN edge costs
no window state and no `-v` noise. They still count in `--top-paths`:
behind a CDN, that is where most real traffic is.

In a replay, a banned client keeps appearing (the bans were not really
applied), so expect it to be banned again after its ttl with a doubled
ttl. Live, voidGate drops its packets and it stops showing up.

## False positives to plan for

- **CGNAT and office egress.** Many users behind one address look like
  one heavy user, but a mixed one: the ratio rule is why they pass. Keep
  `ttl` short anyway.
- **API-only clients** (mobile apps, integrations) have a ratio near 1.0
  by design. `skip` their paths and rate-limit them in nginx instead.
- **Search engines.** `crawler` exempts an address only when its reverse
  DNS ends in a listed domain and that name resolves back to it.
- **Monitoring, health checks.** `allow` them.

## Limits

- **Slow, wide botnets.** Many addresses each under `min_costly` per
  window pass. Per-address rules cannot see them; that needs a global
  signal (e.g. `limit_req` on the endpoint, or a challenge page).
- **Delay.** A ban comes up to one `step` after the threshold is crossed,
  plus nginx log buffering (`access_log ... buffer=` delays it more).
  `resty.voidgate`'s `ban()` reacts on the request itself.
- **Throughput.** About 70k lines/s on one core. Enough for most single
  VMs. Above that, run it under PyPy.
- **Clients that come through a CDN** cannot be banned at XDP (see
  [Behind a CDN](#behind-a-cdn)).
- **No state across restarts.** Offense counts start over; the drops
  themselves live in voidGate and expire on time.

## Tests

```sh
python3 contrib/logban/test_logban.py      # also run by make test
```

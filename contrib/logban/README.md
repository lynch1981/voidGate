# logban: ban costly-URL abusers from the nginx access log

Reads nginx's access log, finds clients that spend nearly all their
requests on expensive endpoints (a CC flood), and drops them at XDP with
`drop <ip> ttl=<sec>`. No Lua needed. Python 3.8+, standard library only.

Design, rules and trade-offs: [`doc/logban.md`](../../doc/logban.md).

## Rule

Per address, over a 60 s sliding window judged every 10 s:

| Rule | Fires when |
|---|---|
| `ratio` | at least 100 costly requests, and at least 90 % of all its requests |
| `backend` | at least `max_backend_seconds` of backend time (off by default) |
| `honey` | one request to a path the site never serves, banned at once |

A request is costly if its path matches a `costly` regex, or its backend
time is at least `slow_seconds`. A ban lasts 600 s and doubles for each
repeat, up to a day.

API clients have a ratio near 1.0 by design. Give them a profile with
their own thresholds, chosen by user agent or path:

```
profile api = ua:^MyShop/
api.ratio = off
api.max_backend_seconds = 30     # half a backend worker per address
```

A forged user agent gets the same limits, not a pass. With a JA4 module,
log `ja4=$http_ssl_ja4` and match your app's TLS stacks instead, which a
script cannot fake with one header:

```
profile app = ja4:^t13d2014h2_a09f3c656075_14788d8d241b$
app.ratio = off
app.max_backend_seconds = 100
profile api_other = path:^/api/       # any other stack: strict
api_other.min_costly = 20
```

JA4 picks thresholds, never a pass: fingerprints change with OS updates
and can be copied ([design §5.5](../../doc/logban.md#55-ja4)).

Honey paths catch scanners on their first probe:

```
honey = ^/(wp-login\.php|xmlrpc\.php|\.env|\.git(/|$))
honey_ttl = 3600                 # doubles on repeats
```

## Log format

`combined` works. Add timing so logban can find costly paths itself:

```nginx
log_format logban '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" rt=$request_time '
                  'urt=$upstream_response_time';
access_log /var/log/nginx/access.log logban;
```

The first field must be the TCP peer: with the realip module on, log
`$realip_remote_addr` there.

## Run

```sh
# Which paths cost the backend most? Write the costly regexes from it.
python3 logban.py -n --top-paths 20 -c logban.conf /var/log/nginx/access.log

# Each client's peak backend seconds per window, with percentiles:
# choose max_backend_seconds from these.
python3 logban.py -n --top-clients 20 -c logban.conf /var/log/nginx/access.log

# Which TLS stacks call you? Build the ja4: profile lines from it.
python3 logban.py -n --top-ja4 20 -c logban.conf /var/log/nginx/access.log

# Replay old logs (gzip works): print what would have been banned.
python3 logban.py -n -c logban.conf /var/log/nginx/access.log.*.gz

# Replay, list the would-be bans, ban only the ones you pick.
sudo python3 logban.py -r -c logban.conf /var/log/nginx/access.log

# Live and dry, then live and enforcing (root or ctl_socket_group).
python3 logban.py -n -f -c logban.conf /var/log/nginx/access.log
sudo python3 logban.py -f -c logban.conf /var/log/nginx/access.log
```

One line per ban:

```
2026-10-03T10:00:30Z ban 203.0.113.1 ttl=600 offense=1 total=150 costly=149 ratio=0.99 backend=178.8s rule=ratio
```

`logban.conf` documents every key: thresholds, `costly`, `profile`,
`honey`, `skip`, `allow`, `allow_file`, `crawler`, ttl.

## Behind Cloudflare

Clients that come through the CDN cannot be banned at XDP; logban bans
the ones that hit the origin directly. Allowlist the CDN
([design §8](../../doc/logban.md#8-behind-a-cdn)):

```sh
sudo mkdir -p /etc/logban
sudo python3 cdn_allow.py cloudflare /etc/logban/cdn-allow.txt
# /etc/cron.d/logban-cdn
17 4 * * *  root  python3 /path/to/cdn_allow.py -q cloudflare /etc/logban/cdn-allow.txt
```

Add `allow_file = /etc/logban/cdn-allow.txt` to `logban.conf`. logban
picks up a new list within one step.

Put the same ranges in voidGate's `allow_networks`. The key replaces the
built-in list, so this keeps the built-ins (256 entries at most):

```sh
echo "allow_networks = 169.254.169.254/32, 127.0.0.0/8, ::1/128," \
     "fe80::/10, ff02::/16, $(grep -v '^#' /etc/logban/cdn-allow.txt |
     paste -sd, | sed 's/,/, /g')"
# paste the line into voidgate.conf, then: sudo voidgatectl reload
```

## Tests

```sh
python3 contrib/logban/test_logban.py      # also run by make test
```

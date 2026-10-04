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

A request is costly if its path matches a `costly` regex, or its backend
time is at least `slow_seconds`. A ban lasts 600 s and doubles for each
repeat, up to a day.

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

`logban.conf` documents every key: thresholds, `costly`, `skip`, `allow`,
`allow_file`, `crawler`, ttl.

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

# logban sample data

| File | What |
|---|---|
| `me.access.log` | A real nginx log, `combined`, no timing fields: a small static site, 20 Sep - 4 Oct 2026, 34,946 lines, mostly scanners. |
| `me.conf` | The logban config built for that site from that log. |
| `clickHouse.access.log` | Generated sample data in nginx JSON (`escape=json`): every line from a different address, one host (`example.com`), evenly spread methods and user agents. Useful to test JSON parsing; nothing in it should be banned. |

Try them:

```sh
cd contrib/logban
python3 logban.py -n -c data/me.conf data/me.access.log    # needs the
#   allow_file: python3 cdn_allow.py cloudflare /etc/logban/cdn-allow.txt
python3 logban.py -n -c data/me.conf -x 80.94.95.211 data/me.access.log
python3 logban.py -n -c logban.conf --top-paths 10 data/clickHouse.access.log
```

`test_logban.py` replays both (`DataTest`); the results are in
`doc/logban.md` section 17.

#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

"""Ban HTTP clients that spend their requests on costly URLs.

Reads an nginx access log (combined format, optionally with rt= and urt=
appended), scores every client address over a sliding window and pushes
`drop <ip> ttl=<sec>` to voidGate's control socket. --dry-run only prints.

A client is banned when, within the window:

    costly >= min_costly  and  costly / total >= ratio      (rule=ratio)
    backend seconds >= max_backend_seconds                   (rule=backend)

A request is costly when its path matches a `costly` regex, or when its
backend time is at least `slow_seconds`. Browsers also fetch pages and
assets that are cheap, so their ratio stays low; a bot hammering one
expensive endpoint scores near 1.0.

See README.md next to this file.
"""

import argparse
import collections
import gzip
import ipaddress
import os
import re
import signal
import socket
import sys
import time
from datetime import datetime


VG_SOCK_PATH = "/run/voidgate.sock"
MAX_TTL = 31536000


# $remote_addr - $remote_user [$time_local] "$request" $status
# $body_bytes_sent "$http_referer" "$http_user_agent" ...
# nginx escapes '"' inside variables as \x22, so [^"]* is safe.
LINE = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) \S+'
    r'(?: "[^"]*" "[^"]*")?(.*)')
# $upstream_response_time has spaces between tries: "0.5, 0.2 : 0.1".
TIMING = re.compile(r'\b(rt|urt)=([-\d.,: ]+)')
NUMBER = re.compile(r'\d+(?:\.\d+)?')


class ConfigError(Exception):
    pass


def warn(msg):
    sys.stderr.write("logban: %s\n" % msg)


def read_cidrs(path):
    """One CIDR (or bare address) per line; # comments."""

    nets = []

    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()

            if not line:
                continue

            try:
                nets.append(ipaddress.ip_network(line, strict=False))

            except ValueError as e:
                raise ConfigError("%s:%d: %s" % (path, lineno, e))

    return nets


class AllowFiles:
    """allow_file lists, re-read when one of them changes. A cron job
    replaces them with mv, so a change is a new inode or mtime."""

    def __init__(self):
        self.paths = []
        self.stamps = None
        self.nets = []

    def stamp(self):
        out = []

        for path in self.paths:
            try:
                st = os.stat(path)
                out.append((st.st_ino, st.st_mtime_ns, st.st_size))

            except OSError:
                out.append(None)

        return out

    def load(self):
        """At startup: any error is fatal."""

        self.stamps = self.stamp()

        try:
            self.nets = [n for p in self.paths for n in read_cidrs(p)]

        except OSError as e:
            raise ConfigError("allow_file: %s" % e)

    def refresh(self):
        """While running: True when the lists changed. A broken update
        keeps the old lists, and is retried only after the next change."""

        stamps = self.stamp()

        if stamps == self.stamps:
            return False

        self.stamps = stamps

        try:
            nets = [n for p in self.paths for n in read_cidrs(p)]

        except (OSError, ConfigError) as e:
            warn("allow_file not reloaded, keeping %d networks: %s"
                 % (len(self.nets), e))
            return False

        warn("allow_file reloaded: %d networks" % len(nets))
        self.nets = nets
        return True


class Config:

    # key: (type, default); list keys may repeat.
    SCALARS = {
        "window": (int, 60),
        "step": (int, 10),
        "min_costly": (int, 100),
        "ratio": (float, 0.9),
        "slow_seconds": (float, 0.0),
        "max_backend_seconds": (float, 0.0),
        "ttl": (int, 600),
        "max_ttl": (int, 86400),
        "offense_memory": (int, 86400),
        "socket": (str, VG_SOCK_PATH),
    }
    LISTS = ("costly", "skip", "allow", "allow_file", "crawler")

    def __init__(self):
        for key, (_, default) in self.SCALARS.items():
            setattr(self, key, default)

        self.costly = []
        self.skip = []
        self.allow = [ipaddress.ip_network("127.0.0.0/8"),
                      ipaddress.ip_network("::1/128")]
        self.allow_files = AllowFiles()
        self.crawler = []

    def load(self, path):
        with open(path) as f:
            for lineno, line in enumerate(f, 1):
                line = line.split("#", 1)[0].strip()

                if not line:
                    continue

                key, sep, value = line.partition("=")
                key, value = key.strip(), value.strip()

                if not sep or not value:
                    raise ConfigError("%s:%d: expected key = value"
                                      % (path, lineno))

                try:
                    self.set(key, value)

                except (ValueError, re.error) as e:
                    raise ConfigError("%s:%d: %s: %s"
                                      % (path, lineno, key, e))

        self.check()

    def set(self, key, value):
        if key in self.SCALARS:
            setattr(self, key, self.SCALARS[key][0](value))

        elif key in ("costly", "skip"):
            getattr(self, key).append(re.compile(value))

        elif key == "allow":
            self.allow.append(ipaddress.ip_network(value, strict=False))

        elif key == "allow_file":
            self.allow_files.paths.append(value)

        elif key == "crawler":
            self.crawler.append("." + value.lstrip("."))

        else:
            raise ValueError("unknown key")

    def check(self):
        self.allow_files.load()

        if self.step < 1 or self.window < self.step:
            raise ConfigError("need 1 <= step <= window")

        if not 0 < self.ratio <= 1:
            raise ConfigError("ratio must be in (0, 1]")

        if not 1 <= self.ttl <= self.max_ttl <= MAX_TTL:
            raise ConfigError("need 1 <= ttl <= max_ttl <= %d" % MAX_TTL)

        if (not self.costly and self.slow_seconds <= 0
                and self.max_backend_seconds <= 0):
            raise ConfigError("nothing is costly: set costly, slow_seconds"
                              " or max_backend_seconds")


_time_cache = {}


def parse_time(s):
    t = _time_cache.get(s)

    if t is None:
        if len(_time_cache) > 4096:
            _time_cache.clear()

        t = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp()
        _time_cache[s] = t

    return t


def parse_line(line):
    """Return (ip, epoch, path, backend_seconds or None), or None."""

    m = LINE.match(line)

    if m is None:
        return None

    ip, stamp, request, _, rest = m.groups()

    try:
        t = parse_time(stamp)

    except ValueError:
        return None

    parts = request.split(" ")
    path = parts[1].split("?", 1)[0] if len(parts) == 3 else ""

    timing = dict(TIMING.findall(rest))
    cost = None

    # urt is "0.010", "-", or one value per upstream tried
    # ("0.010, 0.020 : 0.003"); fall back to rt.
    for key in ("urt", "rt"):
        values = NUMBER.findall(timing.get(key, ""))

        if values:
            cost = sum(float(v) for v in values)
            break

    return ip, t, path, cost


class Window:
    """Per-address [total, costly, backend seconds] over the last
    `buckets` steps, kept as running sums."""

    def __init__(self, step, buckets):
        self.step = step
        self.size = buckets
        self.buckets = collections.deque()
        self.totals = {}
        self.cur = None

    def add(self, ip, costly, cost):
        for d in (self.buckets[-1], self.totals):
            s = d.get(ip)

            if s is None:
                s = d[ip] = [0, 0, 0.0]

            s[0] += 1
            s[1] += costly
            s[2] += cost

    def push(self):
        self.buckets.append({})

        if len(self.buckets) > self.size:
            for ip, s in self.buckets.popleft().items():
                t = self.totals[ip]

                if t[0] == s[0]:
                    del self.totals[ip]
                    continue

                t[0] -= s[0]
                t[1] -= s[1]
                t[2] -= s[2]

    def reset(self):
        self.buckets.clear()
        self.totals.clear()
        self.buckets.append({})

    def remove(self, ip):
        self.totals.pop(ip, None)

        for b in self.buckets:
            b.pop(ip, None)


class Judge:

    def __init__(self, cfg, act, out=sys.stdout, verbose=0,
                 resolve=None):
        self.cfg = cfg
        self.act = act
        self.out = out
        self.verbose = verbose
        self.resolve = resolve or resolve_dns
        self.win = Window(cfg.step, cfg.window // cfg.step)
        self.banned = {}            # ip -> until
        self.offenses = {}          # ip -> (count, last)
        self.listed = {}            # ip -> "allow", "bad-address" or ""
        self.crawlers = {}          # ip -> verified crawler (DNS cache)
        self.paths = {}             # path -> [count, backend seconds]
        self.timed = False
        self.lines = 0
        self.skipped = 0
        self.unjudged = 0
        self.history = None         # list: keep every ban (--review)

    def feed(self, line):
        r = parse_line(line)

        if r is None:
            self.skipped += 1
            return

        ip, t, path, cost = r
        self.lines += 1
        self.clock(t)

        if any(p.search(path) for p in self.cfg.skip):
            return

        if cost is not None:
            self.timed = True

        p = self.paths.get(path)

        if p is None:
            p = self.paths[path] = [0, 0.0]

        p[0] += 1
        p[1] += cost or 0.0

        # An allowed address (a CDN edge) can never be banned: keep it in
        # the path report above, but out of the window.
        if self.listed_reason(ip):
            self.unjudged += 1
            return

        costly = (any(p.search(path) for p in self.cfg.costly)
                  or (cost is not None and self.cfg.slow_seconds > 0
                      and cost >= self.cfg.slow_seconds))

        self.win.add(ip, int(costly), cost or 0.0)

    def clock(self, t):
        """Move the window to time t. A late line (nginx logs a request
        when it ends) is counted in the current bucket."""

        idx = int(t // self.cfg.step)
        win = self.win

        if win.cur is None:
            win.cur = idx
            win.reset()
            return

        if idx <= win.cur:
            return

        if idx - win.cur > win.size:
            # A gap longer than the window: judge once, start over.
            self.judge((win.cur + 1) * self.cfg.step)
            win.reset()
            win.cur = idx
            return

        while win.cur < idx:
            win.cur += 1
            self.judge(win.cur * self.cfg.step)
            win.push()

    def finish(self):
        """Judge the partial window at end of input."""

        if self.win.cur is not None:
            self.judge((self.win.cur + 1) * self.cfg.step)

    def judge(self, now):
        cfg = self.cfg

        if cfg.allow_files.refresh():
            self.listed.clear()

        for ip, (total, costly, cost) in list(self.win.totals.items()):
            if costly >= cfg.min_costly and costly >= cfg.ratio * total:
                rule = "ratio"

            elif cfg.max_backend_seconds > 0 \
                    and cost >= cfg.max_backend_seconds:
                rule = "backend"

            else:
                continue

            if self.banned.get(ip, 0) > now:
                continue

            why = self.exempt_reason(ip)

            if why:
                if self.verbose:
                    self.log("skip %s %s total=%d costly=%d"
                             % (ip, why, total, costly))
                continue

            self.ban(ip, now, rule, total, costly, cost)

    def ban(self, ip, now, rule, total, costly, cost):
        cfg = self.cfg
        count, last = self.offenses.get(ip, (0, 0))

        if now - last > cfg.offense_memory:
            count = 0

        ttl = min(cfg.ttl << min(count, 30), cfg.max_ttl)
        err = self.act(ip, ttl)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

        self.out.write("%s ban %s ttl=%d offense=%d total=%d costly=%d"
                       " ratio=%.2f backend=%.1fs rule=%s%s\n"
                       % (stamp, ip, ttl, count + 1, total, costly,
                          costly / total, cost, rule,
                          " error=" + err if err else ""))
        self.out.flush()

        if err:
            return              # retried at the next step

        self.offenses[ip] = (count + 1, now)
        self.banned[ip] = now + ttl

        if self.history is not None:
            self.history.append((now, ip, ttl, total, costly, cost, rule))
        self.win.remove(ip)

        if len(self.banned) > 65536:
            self.banned = {k: v for k, v in self.banned.items() if v > now}

    def listed_reason(self, ip):
        """Why an address is never judged, or "". Cached: this runs for
        every line, the allowlists only once per address."""

        why = self.listed.get(ip)

        if why is not None:
            return why

        try:
            addr = ipaddress.ip_address(ip)

        except ValueError:
            why = "bad-address"

        else:
            nets = self.cfg.allow + self.cfg.allow_files.nets
            why = "allow" if any(addr in net for net in nets) else ""

        if len(self.listed) > 65536:
            self.listed.clear()

        self.listed[ip] = why
        return why

    def exempt_reason(self, ip):
        """Checked only for an address that matched a rule. Counts made
        before an allow_file reload are still excused; the DNS crawler
        check is too slow to run per line."""

        why = self.listed_reason(ip)

        if why or not self.cfg.crawler:
            return why

        crawler = self.crawlers.get(ip)

        if crawler is None:
            crawler = self.is_crawler(ip)

            if len(self.crawlers) > 65536:
                self.crawlers.clear()

            self.crawlers[ip] = crawler

        return "crawler" if crawler else ""

    def is_crawler(self, ip):
        """Reverse DNS ends in a crawler domain, and that name resolves
        back to ip. The user agent is not trusted."""

        names, addrs = self.resolve(ip)

        for name in names:
            if name.lower().endswith(tuple(self.cfg.crawler)):
                _, back = self.resolve(name)

                if ip in back:
                    return True

        return False

    def report(self, n):
        """Print the paths that cost the backend most (or the most
        requested ones when the log has no timing)."""

        key = (lambda kv: kv[1][1]) if self.timed else (lambda kv: kv[1][0])
        top = sorted(self.paths.items(), key=key, reverse=True)[:n]

        self.out.write("\n%-10s %-12s %-9s path\n"
                       % ("requests", "backend_s", "avg_ms"))

        for path, (count, cost) in top:
            self.out.write("%-10d %-12.1f %-9.1f %s\n"
                           % (count, cost, cost * 1000 / count, path))

        if not self.timed:
            self.out.write("(no rt=/urt= in the log: sorted by requests)\n")

    def log(self, msg):
        warn(msg)


def resolve_dns(name):
    """(names, addresses) for an address (reverse) or a name (forward)."""

    try:
        ipaddress.ip_address(name)

    except ValueError:
        try:
            return [name], {a[4][0] for a in socket.getaddrinfo(name, None)}

        except OSError:
            return [], set()

    try:
        host, aliases, _ = socket.gethostbyaddr(name)

    except OSError:
        return [], set()

    return [host] + aliases, set()


def dry_run(ip, ttl):
    return None


def ctl_drop(path):
    def drop(ip, ttl):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(path)
                s.sendall(b"drop %s ttl=%d\n" % (ip.encode(), ttl))
                s.shutdown(socket.SHUT_WR)
                reply = b""

                while True:
                    chunk = s.recv(4096)

                    if not chunk:
                        break

                    reply += chunk

        except OSError as e:
            return '"%s"' % e

        reply = reply.decode(errors="replace").strip()

        return None if reply == "ok" else '"%s"' % (reply or "no reply")

    return drop


def summarize(history):
    """One row per address, most costly first. The ttl is the last
    (longest) one the replay reached."""

    rows = {}

    for now, ip, ttl, total, costly, cost, rule in history:
        r = rows.get(ip)

        if r is None:
            r = rows[ip] = {"ip": ip, "bans": 0, "total": 0, "costly": 0,
                            "cost": 0.0, "rules": set(), "first": now}

        r["bans"] += 1
        r["ttl"] = ttl
        r["total"] += total
        r["costly"] += costly
        r["cost"] += cost
        r["rules"].add(rule)
        r["last"] = now

    return sorted(rows.values(), key=lambda r: (-r["costly"], r["ip"]))


def print_rows(rows, out):
    width = max(len(r["ip"]) for r in rows)
    out.write("%3s  %-*s %5s %7s %7s %6s %9s  %-13s %s\n"
              % ("#", width, "address", "bans", "ttl", "costly", "ratio",
                 "backend", "rule", "seen (UTC)"))

    for i, r in enumerate(rows, 1):
        seen = time.strftime("%m-%d %H:%M", time.gmtime(r["first"]))

        if r["last"] - r["first"] >= 60:
            seen += time.strftime(" .. %H:%M", time.gmtime(r["last"]))

        out.write("%3d  %-*s %5d %7d %7d %6.2f %8.1fs  %-13s %s\n"
                  % (i, width, r["ip"], r["bans"], r["ttl"], r["costly"],
                     r["costly"] / r["total"], r["cost"],
                     ",".join(sorted(r["rules"])), seen))


def parse_selection(text, n):
    """Row numbers (1-based) picked by "a", "n", or "1-3,7 9"; None when
    the answer does not parse."""

    text = text.strip().lower()

    if text in ("a", "all"):
        return list(range(1, n + 1))

    if text in ("", "n", "none", "q", "quit"):
        return []

    picked = set()

    for word in re.split(r"[,\s]+", text):
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", word)

        if m is None:
            return None

        lo = int(m.group(1))
        hi = int(m.group(2) or lo)

        if not 1 <= lo <= hi <= n:
            return None

        picked.update(range(lo, hi + 1))

    return sorted(picked)


def ask_tty(prompt):
    """Ask on the terminal, not stdin: the log may come from stdin."""

    # Two handles: a text file opened "r+" must be seekable, a tty is not.
    with open("/dev/tty", "w") as w, open("/dev/tty") as r:
        w.write(prompt)
        w.flush()
        answer = r.readline()

    if not answer:
        raise EOFError

    return answer


def review(judge, act, ask, out):
    """Show what the replay would ban, ban only what the user picks.
    Returns the exit code."""

    rows = summarize(judge.history)

    if not rows:
        out.write("nothing to ban\n")
        return 0

    print_rows(rows, out)
    out.flush()

    while True:
        try:
            answer = ask("ban which? [a]ll, [n]one, or numbers like"
                         " 1-3,7: ")

        except EOFError:
            answer = "n"

        picked = parse_selection(answer, len(rows))

        if picked is not None:
            break

        out.write("pick 1 to %d, a or n\n" % len(rows))

    failed = 0

    for i in picked:
        r = rows[i - 1]
        err = act(r["ip"], r["ttl"])
        failed += err is not None
        out.write("%s %s ttl=%d%s\n"
                  % ("ban" if act is not dry_run else "would ban", r["ip"],
                     r["ttl"], " error=" + err if err else ""))

    if not picked:
        out.write("nothing banned\n")

    return 1 if failed else 0


def read_files(paths):
    for path in paths:
        if path == "-":
            yield from sys.stdin
            continue

        opener = gzip.open if path.endswith(".gz") else open

        with opener(path, "rt", errors="replace") as f:
            yield from f


def follow(path, judge, from_start, poll=0.5):
    """tail -F: survive rotation and truncation, and move the window on
    wall-clock time while the log is quiet."""

    f = None
    partial = ""

    while True:
        if f is None:
            try:
                f = open(path, errors="replace")

            except FileNotFoundError:
                time.sleep(poll)
                continue

            ino = os.fstat(f.fileno()).st_ino

            if not from_start:
                f.seek(0, os.SEEK_END)

            from_start = True       # every later file is read whole

        line = f.readline()

        if line:
            if not line.endswith("\n"):
                partial += line
                continue

            judge.feed(partial + line)
            partial = ""
            continue

        judge.clock(time.time())
        time.sleep(poll)

        try:
            st = os.stat(path)

        except FileNotFoundError:
            continue

        if st.st_ino != ino or st.st_size < f.tell():
            f.close()
            f = None
            partial = ""


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Ban clients that spend their requests on costly URLs.")
    ap.add_argument("logs", nargs="+",
                    help="access log(s); .gz and - (stdin) work")
    ap.add_argument("-c", "--config", help="key = value config file")
    ap.add_argument("-n", "--dry-run", action="store_true",
                    help="print bans, send nothing")
    ap.add_argument("-f", "--follow", action="store_true",
                    help="follow one log like tail -F")
    ap.add_argument("-r", "--review", action="store_true",
                    help="replay, list the bans, ban only those you pick")
    ap.add_argument("--from-start", action="store_true",
                    help="with -f, read the existing file first")
    ap.add_argument("--top-paths", type=int, metavar="N", default=0,
                    help="at the end, print the N costliest paths")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args(argv)

    cfg = Config()

    try:
        if args.config:
            cfg.load(args.config)

        else:
            cfg.check()

    except (OSError, ConfigError) as e:
        sys.stderr.write("logban: %s\n" % e)
        return 1

    act = dry_run if args.dry_run else ctl_drop(cfg.socket)

    if args.review:
        if args.follow:
            sys.stderr.write("logban: --review replays logs, not -f\n")
            return 1

        # Judge as a dry run; bans happen after the user picks them.
        judge = Judge(cfg, dry_run, out=open(os.devnull, "w"),
                      verbose=args.verbose)
        judge.history = []

    else:
        judge = Judge(cfg, act, verbose=args.verbose)

    if args.follow:
        if len(args.logs) != 1 or args.logs[0] == "-":
            sys.stderr.write("logban: -f takes one log file\n")
            return 1

        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

        try:
            follow(args.logs[0], judge, args.from_start)

        except KeyboardInterrupt:
            return 0

    try:
        for line in read_files(args.logs):
            judge.feed(line)

    except OSError as e:
        sys.stderr.write("logban: %s\n" % e)
        return 1

    judge.finish()

    if args.verbose or args.top_paths:
        sys.stderr.write("logban: %d lines, %d unparsed, %d allowed\n"
                         % (judge.lines + judge.skipped, judge.skipped,
                            judge.unjudged))

    if args.top_paths:
        judge.report(args.top_paths)

    if args.review:
        try:
            return review(judge, act, ask_tty, sys.stdout)

        except OSError as e:
            sys.stderr.write("logban: --review needs a terminal: %s\n" % e)
            return 1

        except KeyboardInterrupt:
            sys.stdout.write("\nnothing banned\n")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

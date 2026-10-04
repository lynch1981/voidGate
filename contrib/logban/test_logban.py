#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

"""Unit tests for logban.py. No root, no daemon: python3 test_logban.py"""

import io
import os
import socket
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cdn_allow  # noqa: E402
import logban  # noqa: E402


T0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc).timestamp()


def line(ip, t, path, rt=None, urt=None, ua="Mozilla/5.0"):
    stamp = datetime.fromtimestamp(t, timezone.utc).strftime(
        "%d/%b/%Y:%H:%M:%S +0000")
    s = '%s - - [%s] "GET %s HTTP/1.1" 200 512 "-" "%s"' % (
        ip, stamp, path, ua)

    if rt is not None:
        s += " rt=%s urt=%s" % (rt, urt if urt is not None else "-")

    return s + "\n"


def config(**kw):
    cfg = logban.Config()
    cfg.costly = [logban.re.compile("^/search")]

    for k, v in kw.items():
        if k in logban.Config.LISTS:
            for x in v:
                cfg.set(k, x)
        else:
            setattr(cfg, k, v)

    cfg.check()
    return cfg


class Recorder:

    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def __call__(self, ip, ttl):
        self.calls.append((ip, ttl))
        return self.fail


def run(cfg, lines, act=None, resolve=None):
    act = act or Recorder()
    out = io.StringIO()
    judge = logban.Judge(cfg, act, out=out, resolve=resolve)

    for s in lines:
        judge.feed(s)

    judge.finish()
    return act, out.getvalue(), judge


def bot(ip, n=200, path="/search?q=x", start=T0, every=0.2, **kw):
    return [line(ip, start + i * every, path, **kw) for i in range(n)]


def browser(ip, n=200, start=T0, every=0.2):
    paths = ["/", "/search?q=a", "/css/a.css", "/js/a.js", "/img/1.png"]

    return [line(ip, start + i * every, paths[i % len(paths)])
            for i in range(n)]


def merge(*streams):
    def when(s):
        return logban.parse_line(s)[1]

    return sorted((s for st in streams for s in st), key=when)


class ParseTest(unittest.TestCase):

    def test_combined(self):
        self.assertEqual(logban.parse_line(
            line("203.0.113.7", T0, "/search?q=1")),
            ("203.0.113.7", T0, "/search", None, "Mozilla/5.0"))

    def test_timing(self):
        self.assertEqual(logban.parse_line(
            line("::1", T0, "/", rt="0.900", urt="0.800"))[3], 0.8)
        # several upstreams tried
        self.assertAlmostEqual(logban.parse_line(
            line("::1", T0, "/", rt="1", urt="0.5, 0.25 : 0.125"))[3],
            0.875)
        # served by nginx itself: urt=- falls back to rt
        self.assertEqual(logban.parse_line(
            line("::1", T0, "/", rt="0.002", urt="-"))[3], 0.002)

    def test_ipv6_and_timezone(self):
        s = ('2001:db8::7 - - [03/Oct/2026:18:00:00 +0800] "GET / HTTP/1.1"'
             ' 200 1 "-" "-"\n')
        self.assertEqual(logban.parse_line(s)[:2], ("2001:db8::7", T0))

    def test_garbage(self):
        self.assertIsNone(logban.parse_line("not a log line\n"))
        # a bad request line still parses, with no path
        s = ('198.51.100.1 - - [03/Oct/2026:10:00:00 +0000] "\\x16\\x03"'
             ' 400 0 "-" "-"\n')
        self.assertEqual(logban.parse_line(s)[2], "")


class JudgeTest(unittest.TestCase):

    def test_bot_banned_browser_not(self):
        act, out, _ = run(config(), merge(bot("203.0.113.7"),
                                          browser("198.51.100.9")))
        self.assertEqual(act.calls, [("203.0.113.7", 600)])
        self.assertIn("ban 203.0.113.7 ttl=600 offense=1 total=", out)
        self.assertIn("rule=ratio", out)

    def test_ipv6_bot(self):
        act, _, _ = run(config(), bot("2001:db8::bad"))
        self.assertEqual(act.calls, [("2001:db8::bad", 600)])

    def test_below_min_costly(self):
        act, _, _ = run(config(), bot("203.0.113.7", n=99))
        self.assertEqual(act.calls, [])

    def test_ratio_threshold(self):
        # 150 costly + 30 cheap: ratio 0.83 < 0.9
        lines = merge(bot("203.0.113.7", n=150),
                      bot("203.0.113.7", n=30, path="/", start=T0 + 0.1))
        act, _, _ = run(config(), lines)
        self.assertEqual(act.calls, [])

        act, _, _ = run(config(ratio=0.8), lines)
        self.assertEqual(len(act.calls), 1)

    def test_window_slides(self):
        # 200 costly requests spread over 10 minutes: never 100 in 60 s
        act, _, _ = run(config(), bot("203.0.113.7", n=200, every=3))
        self.assertEqual(act.calls, [])

    def test_slow_seconds(self):
        cfg = config(slow_seconds=1.0)
        cfg.costly = []
        act, _, _ = run(cfg, bot("203.0.113.7", path="/x", rt="2",
                                 urt="1.5"))
        self.assertEqual(len(act.calls), 1)

        act, _, _ = run(cfg, bot("203.0.113.7", path="/x", rt="0.1",
                                 urt="0.1"))
        self.assertEqual(act.calls, [])

    def test_backend_rule(self):
        # 50 requests, under min_costly, but 50 backend seconds
        cfg = config(max_backend_seconds=30)
        act, out, _ = run(cfg, bot("203.0.113.7", n=50, path="/",
                                   rt="1", urt="1"))
        self.assertEqual(len(act.calls), 1)
        self.assertIn("rule=backend", out)

    def test_skip(self):
        act, _, _ = run(config(skip=["^/search"]), bot("203.0.113.7"))
        self.assertEqual(act.calls, [])

    def test_allow(self):
        lines = merge(bot("192.0.2.5"), bot("127.0.0.1"), bot("::1"))
        act, _, _ = run(config(allow=["192.0.2.0/24"]), lines)
        self.assertEqual(act.calls, [])

    def test_crawler_verified(self):
        dns = {
            "66.249.66.1": (["crawl-66-249-66-1.googlebot.com"], set()),
            "crawl-66-249-66-1.googlebot.com": ([], {"66.249.66.1"}),
            # claims googlebot in DNS, forward does not confirm
            "203.0.113.7": (["fake.googlebot.com"], set()),
            "fake.googlebot.com": ([], {"198.51.100.1"}),
        }
        lines = merge(bot("66.249.66.1"), bot("203.0.113.7"))
        act, _, _ = run(config(crawler=["googlebot.com"]), lines,
                        resolve=lambda n: dns.get(n, ([], set())))
        self.assertEqual(act.calls, [("203.0.113.7", 600)])

    def test_no_reban_while_banned(self):
        # 5 minutes of bot traffic (as in a dry-run replay, where the
        # ban does not stop it): one ban, not one per step
        act, _, _ = run(config(), bot("203.0.113.7", n=1500))
        self.assertEqual(len(act.calls), 1)

    def test_ttl_escalates(self):
        cfg = config(ttl=60, max_ttl=200)
        lines = []

        for k in range(4):
            lines += bot("203.0.113.7", start=T0 + k * 600)

        act, _, _ = run(cfg, lines)
        self.assertEqual([t for _, t in act.calls], [60, 120, 200, 200])

    def test_offense_forgotten(self):
        cfg = config(ttl=60, offense_memory=3600)
        lines = bot("203.0.113.7") + bot("203.0.113.7", start=T0 + 7200)
        act, _, _ = run(cfg, lines)
        self.assertEqual([t for _, t in act.calls], [60, 60])

    def test_failed_ban_retried(self):
        act = Recorder(fail='"error: refused or map update failed"')
        _, out, _ = run(config(), bot("203.0.113.7", n=300), act=act)
        self.assertGreater(len(act.calls), 1)
        self.assertIn("error=", out)

    def test_late_line_counts(self):
        # nginx logs when a request ends: older stamps arrive late
        lines = bot("203.0.113.7", n=100, start=T0 + 30)
        lines.insert(50, line("198.51.100.1", T0, "/"))
        act, _, _ = run(config(), lines)
        self.assertEqual(len(act.calls), 1)

    def test_report(self):
        _, _, judge = run(config(), bot("203.0.113.7", rt="0.5",
                                        urt="0.5"))
        out = io.StringIO()
        judge.out = out
        judge.report_paths(5)
        self.assertIn("/search", out.getvalue())
        self.assertIn("200", out.getvalue())


class ConfigTest(unittest.TestCase):

    def load(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                         delete=False) as f:
            f.write(text)

        try:
            cfg = logban.Config()
            cfg.load(f.name)
            return cfg

        finally:
            os.unlink(f.name)

    def test_example(self):
        here = os.path.dirname(os.path.abspath(__file__))
        cfg = logban.Config()
        cfg.load(os.path.join(here, "logban.conf"))
        self.assertEqual(len(cfg.costly), 3)
        self.assertEqual(cfg.slow_seconds, 0.5)

    def test_errors(self):
        for text in ("bogus = 1\n", "window\n", "ratio = 2\n",
                     "costly = (\n", "allow = 300.0.0.0/8\n",
                     "ttl = 0\ncostly = x\n", "min_costly = 5\n"):
            with self.assertRaises(logban.ConfigError, msg=text):
                self.load(text)


class SocketTest(unittest.TestCase):

    def serve(self, reply):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "vg.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)
        got = []

        def one():
            c, _ = srv.accept()
            data = b""

            while not data.endswith(b"\n"):
                data += c.recv(256)

            got.append(data)
            c.sendall(reply)
            c.close()
            srv.close()

        th = threading.Thread(target=one)
        th.start()
        return path, got, th

    def test_ok(self):
        path, got, th = self.serve(b"ok\n")
        self.assertIsNone(logban.ctl_drop(path)("203.0.113.7", 600))
        th.join()
        self.assertEqual(got, [b"drop 203.0.113.7 ttl=600\n"])

    def test_refused(self):
        path, _, th = self.serve(b"error: refused or map update failed\n")
        err = logban.ctl_drop(path)("2001:db8::1", 60)
        th.join()
        self.assertIn("refused", err)

    def test_no_daemon(self):
        self.assertIsNotNone(logban.ctl_drop("/nonexistent/sock")("::2", 1))


class FollowTest(unittest.TestCase):

    def test_rotation(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "access.log")
        open(path, "w").close()
        act = Recorder()
        judge = logban.Judge(config(), act, out=io.StringIO())
        th = threading.Thread(target=logban.follow,
                              args=(path, judge, False, 0.05), daemon=True)
        th.start()
        logban.time.sleep(0.2)          # follow() opens at end of file

        def write(lines):
            with open(path, "a") as f:
                f.writelines(lines)

        # Live stamps: idle polls move the window on wall-clock time.
        # Rotate before any ban, so the bot's count spans both files.
        now = logban.time.time()
        write(bot("203.0.113.7", n=60, start=now, every=0.01))
        logban.time.sleep(0.3)
        os.rename(path, path + ".1")
        write(bot("203.0.113.7", n=60, start=now + 1, every=0.01))
        write([line("198.51.100.1", now + 30, "/")])

        for _ in range(100):
            if act.calls:
                break
            logban.time.sleep(0.05)

        self.assertEqual(act.calls, [("203.0.113.7", 600)])


class AllowFileTest(unittest.TestCase):

    def setUp(self):
        # reload warnings are expected here
        self.stderr, sys.stderr = sys.stderr, io.StringIO()
        self.addCleanup(setattr, sys, "stderr", self.stderr)
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "cdn.txt")
        self.put("# cloudflare\n173.245.48.0/20\n\n2606:4700::/32  # v6\n")

    def put(self, text):
        # as cron does it: a new file renamed over the old one
        tmp = self.path + ".tmp"

        with open(tmp, "w") as f:
            f.write(text)

        os.rename(tmp, self.path)

    def bots(self, start=T0):
        return merge(bot("173.245.48.9", start=start),
                     bot("2606:4700::1", start=start),
                     bot("203.0.113.7", start=start))

    def test_allowed(self):
        act, _, _ = run(config(allow_file=[self.path]), self.bots())
        self.assertEqual(act.calls, [("203.0.113.7", 600)])

    def test_not_in_window(self):
        cfg = config(allow_file=[self.path], allow=["192.0.2.0/24"])
        judge = logban.Judge(cfg, Recorder(), out=io.StringIO())
        lines = merge(self.bots(), bot("192.0.2.1", n=50),
                      [line("-", T0 + 1, "/search")])
        parsed = []
        ip_address = logban.ipaddress.ip_address

        def count(ip):
            parsed.append(ip)
            return ip_address(ip)

        logban.ipaddress.ip_address = count

        try:
            for s in lines:
                judge.feed(s)

        finally:
            logban.ipaddress.ip_address = ip_address

        self.assertEqual(set(judge.win.totals), {("203.0.113.7", 0)})
        self.assertEqual(judge.unjudged, 451)
        # the path report still sees CDN traffic
        self.assertEqual(judge.paths["/search"][0], 651)
        # the allowlists are checked once per address, not per line
        self.assertEqual(sorted(parsed),
                         sorted(["173.245.48.9", "2606:4700::1",
                                 "203.0.113.7", "192.0.2.1", "-"]))

    def test_newly_allowed_counts_excused(self):
        # Counted before the reload, allowed after it: not banned on the
        # counts it already has in the window.
        os.unlink(self.path)
        self.put("2606:4700::/32\n")
        act = Recorder()
        judge = logban.Judge(config(allow_file=[self.path]), act,
                             out=io.StringIO())

        for s in bot("173.245.48.9", n=99):
            judge.feed(s)

        self.assertIn(("173.245.48.9", 0), judge.win.totals)
        self.put("173.245.48.0/20\n")

        for s in bot("173.245.48.9", n=50, start=T0 + 20):
            judge.feed(s)

        judge.finish()
        self.assertEqual(act.calls, [])

    def test_missing_or_bad_at_start(self):
        with self.assertRaises(logban.ConfigError):
            config(allow_file=[self.path + ".missing"])

        self.put("173.245.48.0/20\nnot-a-cidr\n")

        with self.assertRaisesRegex(logban.ConfigError, r"cdn.txt:2"):
            config(allow_file=[self.path])

    def test_reload(self):
        act = Recorder()
        judge = logban.Judge(config(allow_file=[self.path]), act,
                             out=io.StringIO())

        for s in self.bots():
            judge.feed(s)

        judge.clock(T0 + 1800)      # judge and empty the first window
        self.assertEqual([ip for ip, _ in act.calls], ["203.0.113.7"])

        # the CDN drops a range: its next abuser is banned
        self.put("2606:4700::/32\n")

        for s in self.bots(start=T0 + 3600):
            judge.feed(s)

        judge.finish()
        self.assertEqual(sorted(ip for ip, _ in act.calls),
                         ["173.245.48.9", "203.0.113.7", "203.0.113.7"])

    def test_bad_reload_keeps_old(self):
        act = Recorder()
        judge = logban.Judge(config(allow_file=[self.path]), act,
                             out=io.StringIO())
        os.unlink(self.path)

        for s in self.bots():
            judge.feed(s)

        self.put("garbage\n")

        for s in self.bots(start=T0 + 3600):
            judge.feed(s)

        judge.finish()
        self.assertEqual({ip for ip, _ in act.calls}, {"203.0.113.7"})


CF = (b'{"result":{"ipv4_cidrs":["173.245.48.0/20","104.16.0.0/13"],'
      b'"ipv6_cidrs":["2606:4700::/32"],"etag":"x"},"success":true,'
      b'"errors":[],"messages":[]}')


class CdnAllowTest(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(cdn_allow.check(cdn_allow.cloudflare(CF)),
                         ["104.16.0.0/13", "173.245.48.0/20",
                          "2606:4700::/32"])

    def test_refuse(self):
        bad = [
            b'{"success":false,"errors":[{"code":1}]}',
            b'{"result":{"ipv4_cidrs":[],"ipv6_cidrs":["::/0"]},'
            b'"success":true}',
            b'{"result":{"ipv4_cidrs":["1.0.0.0/24"],"ipv6_cidrs":[]},'
            b'"success":true}',
            b'{"result":{"ipv4_cidrs":["0.0.0.0/0"],'
            b'"ipv6_cidrs":["2606:4700::/32"]},"success":true}',
            b'{"result":{"ipv4_cidrs":["1.2.3/24"],'
            b'"ipv6_cidrs":["2606:4700::/32"]},"success":true}',
            b'{"result":{"ipv4_cidrs":[7],'
            b'"ipv6_cidrs":["2606:4700::/32"]},"success":true}',
            b'<html>',
        ]

        for data in bad:
            with self.assertRaises((ValueError, KeyError, TypeError),
                                   msg=data):
                cdn_allow.check(cdn_allow.cloudflare(data))

    def fetch(self, data, path):
        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def urlopen(req, timeout):
            if isinstance(data, Exception):
                raise data

            return Resp(data)

        saved = cdn_allow.urllib.request.urlopen, sys.stderr
        cdn_allow.urllib.request.urlopen = urlopen
        sys.stderr = io.StringIO()

        try:
            return cdn_allow.main(["-q", "cloudflare", path])

        finally:
            cdn_allow.urllib.request.urlopen, sys.stderr = saved

    def test_write_and_reload_into_logban(self):
        path = os.path.join(tempfile.mkdtemp(), "cdn.txt")
        self.assertEqual(self.fetch(CF, path), 0)
        self.assertEqual(len(logban.read_cidrs(path)), 3)

        ino = os.stat(path).st_ino
        self.assertEqual(self.fetch(CF, path), 0)
        self.assertEqual(os.stat(path).st_ino, ino, "unchanged: no rewrite")

        cfg = config(allow_file=[path])
        act, _, _ = run(cfg, bot("104.16.1.1"))
        self.assertEqual(act.calls, [])

    def test_failure_keeps_file(self):
        path = os.path.join(tempfile.mkdtemp(), "cdn.txt")
        self.fetch(CF, path)

        with open(path) as f:
            before = f.read()

        self.assertEqual(self.fetch(OSError("timed out"), path), 1)
        self.assertEqual(self.fetch(b'{"success":false}', path), 1)

        with open(path) as f:
            self.assertEqual(f.read(), before)

        self.assertEqual(os.listdir(os.path.dirname(path)), ["cdn.txt"])


class ReviewTest(unittest.TestCase):

    def replay(self):
        act = Recorder()
        judge = logban.Judge(config(ttl=60), logban.dry_run,
                             out=io.StringIO())
        judge.history = []
        lines = merge(bot("203.0.113.7", n=300),
                      bot("203.0.113.8", n=150),
                      bot("2001:db8::9", n=200),
                      bot("203.0.113.7", n=200, start=T0 + 600),
                      browser("198.51.100.9"))

        for s in lines:
            judge.feed(s)

        judge.finish()
        return judge, act

    def review(self, answers, act=None):
        judge, rec = self.replay()
        act = act or rec
        answers = iter(answers)
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            a = next(answers, None)

            if a is None:
                raise EOFError

            return a

        out = io.StringIO()
        code = logban.review(judge, act, ask, out)
        return code, act, out.getvalue(), prompts

    def test_selection(self):
        sel = logban.parse_selection

        self.assertEqual(sel("a", 4), [1, 2, 3, 4])
        self.assertEqual(sel("ALL\n", 2), [1, 2])

        for none in ("", "\n", "n", "none", "q"):
            self.assertEqual(sel(none, 4), [])

        self.assertEqual(sel("1-3,7", 9), [1, 2, 3, 7])
        self.assertEqual(sel(" 2  1, 2-2 ", 3), [1, 2])

        for bad in ("0", "5", "3-1", "1-", "x", "1;2", "-1", "a,1"):
            self.assertIsNone(sel(bad, 4), bad)

    def test_table(self):
        code, act, out, _ = self.review(["n\n"])
        rows = out.splitlines()

        self.assertEqual(code, 0)
        self.assertEqual(act.calls, [])
        self.assertIn("address", rows[0])
        # one row per address, most costly first; the browser is absent
        self.assertRegex(rows[1], r"^  1  203\.0\.113\.7 +2 +120 ")
        self.assertRegex(rows[2], r"^  2  2001:db8::9 +1 +60 ")
        self.assertRegex(rows[3], r"^  3  203\.0\.113\.8 +1 +60 ")
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[4], "nothing banned")

    def test_pick(self):
        code, act, out, prompts = self.review(["9\n", "1,3\n"])

        self.assertEqual(code, 0)
        self.assertEqual(len(prompts), 2)
        self.assertIn("pick 1 to 3, a or n", out)
        self.assertEqual(act.calls,
                         [("203.0.113.7", 120), ("203.0.113.8", 60)])
        self.assertIn("ban 203.0.113.8 ttl=60\n", out)

    def test_eof_bans_nothing(self):
        code, act, out, _ = self.review([])
        self.assertEqual((code, act.calls), (0, []))
        self.assertIn("nothing banned", out)

    def test_failure(self):
        code, act, out, _ = self.review(
            ["a\n"], act=Recorder(fail='"error: refused"'))
        self.assertEqual(code, 1)
        self.assertEqual(len(act.calls), 3)
        self.assertIn('error="error: refused"', out)

    def test_dry(self):
        code, _, out, _ = self.review(["a\n"], act=logban.dry_run)
        self.assertEqual(code, 0)
        self.assertIn("would ban 203.0.113.7 ttl=120", out)

    def test_nothing(self):
        judge = logban.Judge(config(), logban.dry_run, out=io.StringIO())
        judge.history = []
        out = io.StringIO()
        self.assertEqual(logban.review(judge, Recorder(), None, out), 0)
        self.assertEqual(out.getvalue(), "nothing to ban\n")

    def test_not_with_follow(self):
        err = io.StringIO()
        saved, sys.stderr = sys.stderr, err

        try:
            conf = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "logban.conf")
            self.assertEqual(logban.main(["-c", conf, "-r", "-f", "x.log"]),
                             1)

        finally:
            sys.stderr = saved

        self.assertIn("--review", err.getvalue())


class TopClientsTest(unittest.TestCase):

    def report(self, lines, n=10, **kw):
        out = io.StringIO()
        judge = logban.Judge(config(**kw), Recorder(), out=out)
        judge.peaks = {}

        for s in lines:
            judge.feed(s)

        judge.finish()
        judge.report_clients(n)
        return judge, out.getvalue()

    def test_peaks(self):
        # 100 x 0.5 s in 20 s, then 20 x 0.5 s a minute later
        lines = (bot("198.51.100.1", n=100, path="/x", rt="0.6", urt="0.5")
                 + bot("198.51.100.1", n=20, path="/x", rt="0.6",
                       urt="0.5", start=T0 + 120)
                 + bot("198.51.100.2", n=10, path="/x", rt="1", urt="1"))
        judge, out = self.report(sorted(lines,
                                        key=lambda s: logban.parse_line(s)[1]))

        self.assertEqual(judge.peaks[("198.51.100.1", 0)],
                         [50.0, 100, 0, 120])
        self.assertEqual(judge.peaks[("198.51.100.2", 0)], [10.0, 10, 0, 10])
        rows = out.splitlines()
        self.assertIn("peak backend seconds", rows[1])
        self.assertRegex(rows[3], r"^  1  198\.51\.100\.1  default +50\.0"
                                  r" +0\.83 +100 ")
        self.assertIn("default       2 clients  p50 10.0  p90 50.0", out)

    def test_banned_flagged_not_in_percentiles(self):
        lines = merge(bot("203.0.113.7", rt="0.5", urt="0.5"),
                      bot("198.51.100.1", n=40, path="/", rt="0.1",
                          urt="0.1"))
        _, out = self.report(lines)
        self.assertRegex(out, r"203\.0\.113\.7 .* yes\n")
        self.assertIn("default       1 clients  p50 4.0", out)

    def test_allowlisted_not_shown(self):
        lines = merge(bot("192.0.2.1", rt="1", urt="1"),
                      bot("198.51.100.1", n=5, rt="1", urt="1"))
        judge, out = self.report(lines, allow=["192.0.2.0/24"])
        self.assertEqual(set(judge.peaks), {("198.51.100.1", 0)})
        self.assertNotIn("192.0.2.1", out)

    def test_no_timing(self):
        lines = merge(bot("198.51.100.1", n=30), bot("198.51.100.2", n=60))
        _, out = self.report(lines, n=1)
        self.assertIn("peak requests", out)
        self.assertIn("198.51.100.2", out)
        self.assertNotIn("198.51.100.1 ", out)
        self.assertIn("(no rt=/urt=", out)

    def test_off_by_default(self):
        _, _, judge = run(config(), bot("198.51.100.1", n=5))
        self.assertIsNone(judge.peaks)


APP = "MyShop/5.2.1 (iOS 18.0)"


def app(ip, n=200, path="/api/search", start=T0, every=0.2, urt="0.05"):
    return bot(ip, n=n, path=path, start=start, every=every, rt=urt,
               urt=urt, ua=APP)


def api_config(**kw):
    cfg = logban.Config()
    lines = ["costly = ^/search", "costly = ^/api/search",
             "profile api = ua:^MyShop/", "api.ratio = off",
             "api.max_backend_seconds = 30"]
    lines += ["%s = %s" % kv for kv in kw.items()]

    for ln in lines:
        k, _, v = ln.partition("=")
        cfg.set(k.strip(), v.strip())

    cfg.check()
    return cfg


class ProfileTest(unittest.TestCase):

    def test_config(self):
        cfg = api_config(min_costly=50)
        default, api = cfg.profiles

        self.assertEqual((default.name, default.prefix), ("default", ""))
        self.assertEqual((default.min_costly, default.ratio,
                          default.max_backend_seconds), (50, 0.9, 0.0))
        self.assertEqual((api.name, api.prefix), ("api", "api."))
        self.assertEqual((api.min_costly, api.ratio,
                          api.max_backend_seconds), (50, None, 30.0))

    def test_config_errors(self):
        base = "costly = x\n"

        for text in ("profile api = ua\n",            # no field
                     "profile api = agent:x\n",       # unknown field
                     "profile api = ua:\n",           # empty regex
                     "profile api = ua:(\n",          # bad regex
                     "profile Api = ua:x\n",          # bad name
                     "profile default = ua:x\n",      # reserved
                     "api.ratio = 0.5\n",             # undeclared
                     "profile api = ua:x\napi.ratio = 2\n",
                     "profile api = ua:x\napi.min_costly = 0\n",
                     # declared, but nothing can fire
                     "profile api = ua:x\napi.ratio = off\n",
                     "profile api = ua:x\napi.bogus = 1\n"):
            with self.assertRaises(logban.ConfigError, msg=text):
                ConfigTest.load(self, base + text)

        # ratio off everywhere and no backend rule: nothing can fire
        with self.assertRaises(logban.ConfigError):
            ConfigTest.load(self, base + "ratio = off\n")

        # default may judge nothing while a profile does
        cfg = ConfigTest.load(self, "ratio = off\nprofile api = path:^/a"
                                    "\napi.max_backend_seconds = 5\n")
        self.assertIsNone(cfg.profiles[0].ratio)

    def test_matching(self):
        cfg = api_config()
        cfg.set("profile export", "path:^/export/")
        cfg.set("profile export", "ua:^ExportBot/")
        cfg.set("export.max_backend_seconds", "300")
        cfg.check()
        judge = logban.Judge(cfg, Recorder(), out=io.StringIO())
        of = judge.profile_of

        self.assertEqual(of("/", "Mozilla/5.0"), 0)
        self.assertEqual(of("/api/search", APP), 1)
        self.assertEqual(of("/export/x", "Mozilla/5.0"), 2)
        self.assertEqual(of("/", "ExportBot/1"), 2)
        # the first declared profile wins
        self.assertEqual(of("/export/x", APP), 1)
        # no user agent in the log: only path profiles can match
        self.assertEqual(of("/", ""), 0)

    def test_api_ratio_off(self):
        # A real app: every request costly, little backend time
        lines = app("198.51.100.7")

        act, _, _ = run(api_config(), lines)
        self.assertEqual(act.calls, [])

        # the same traffic without the profile is banned by ratio
        act, _, _ = run(config(costly=["^/api/search"]), lines)
        self.assertEqual(len(act.calls), 1)

    def test_faked_ua_still_banned(self):
        # A bot copying the app's user agent gets the app's thresholds,
        # not a pass: 200 x 0.5 s in 40 s crosses 30 backend seconds.
        act, out, _ = run(api_config(), app("203.0.113.7", urt="0.5"))
        self.assertEqual(act.calls, [("203.0.113.7", 600)])
        self.assertIn("rule=api.backend", out)

    def test_counted_apart(self):
        # One NAT address: the app's costly calls do not push the
        # browsers' ratio over the line.
        lines = merge(app("100.64.0.1"),
                      browser("100.64.0.1", n=10, every=4))
        act, _, judge = run(api_config(), lines)
        self.assertEqual(act.calls, [])

        act, _, _ = run(api_config(**{"api.max_backend_seconds": "0",
                                      "api.ratio": "0.9"}), lines)
        self.assertEqual(len(act.calls), 1)

    def test_ban_clears_every_profile(self):
        cfg = api_config()
        judge = logban.Judge(cfg, Recorder(), out=io.StringIO())

        # the ban comes at end of input, so no line re-enters after it
        for s in merge(app("203.0.113.7", n=20),
                       bot("203.0.113.7", n=100)):
            judge.feed(s)

        self.assertEqual({k[1] for k in judge.win.totals}, {0, 1})
        judge.finish()
        self.assertEqual(len(judge.act.calls), 1)
        self.assertEqual(judge.win.totals, {})

    def test_top_clients_per_profile(self):
        cfg = api_config()
        out = io.StringIO()
        judge = logban.Judge(cfg, Recorder(), out=out)
        judge.peaks = {}

        for s in merge(app("198.51.100.7", n=100),
                       browser("198.51.100.7", n=20),
                       browser("198.51.100.8", n=20)):
            judge.feed(s)

        judge.finish()
        judge.report_clients(10)
        text = out.getvalue()

        self.assertEqual(sorted(judge.peaks),
                         [("198.51.100.7", 0), ("198.51.100.7", 1),
                          ("198.51.100.8", 0)])
        self.assertRegex(text, r"198\.51\.100\.7  api +5\.0 ")
        self.assertRegex(text, r"\n  default +2 clients ")
        self.assertRegex(text, r"\n  api +1 clients  p50 5\.0")


if __name__ == "__main__":
    unittest.main()

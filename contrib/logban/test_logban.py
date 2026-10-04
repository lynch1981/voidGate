#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

"""Unit tests for logban.py. No root, no daemon: python3 test_logban.py"""

import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cdn_allow  # noqa: E402
import logban  # noqa: E402


T0 = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc).timestamp()


def line(ip, t, path, rt=None, urt=None, ua="Mozilla/5.0", ja4=None,
         method="GET", status=200):
    stamp = datetime.fromtimestamp(t, timezone.utc).strftime(
        "%d/%b/%Y:%H:%M:%S +0000")
    s = '%s - - [%s] "%s %s HTTP/1.1" %d 512 "-" "%s"' % (
        ip, stamp, method, path, status, ua)

    if rt is not None:
        s += " rt=%s urt=%s" % (rt, urt if urt is not None else "-")

    if ja4 is not None:
        s += " ja4=%s" % ja4

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
            ("203.0.113.7", T0, "/search", None, "Mozilla/5.0", "", "GET",
             "200"))

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

    def test_refused_held_for_ttl(self):
        # 5 minutes of flood from an address the daemon protects: one
        # refusal, not one per step, and no offense counted
        act = Recorder(fail=logban.Refused('"error: refused or map update'
                                           ' failed"'))
        _, out, judge = run(config(), bot("198.51.100.10", n=1500), act=act)

        self.assertEqual(len(act.calls), 1)
        self.assertEqual(out.count("\n"), 1)
        self.assertIn('error="error: refused or map update failed"'
                      ' retry_after=600s', out)
        self.assertNotIn("198.51.100.10", judge.offenses)

    def test_refused_tried_again_after_ttl(self):
        act = Recorder(fail=logban.Refused('"error: refused"'))
        lines = bot("198.51.100.10") + bot("198.51.100.10", start=T0 + 900)
        run(config(), lines, act=act)
        self.assertEqual([t for _, t in act.calls], [600, 600])

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
        self.assertIsInstance(err, logban.Refused)

    def test_no_reply(self):
        # the daemon closed without answering: not a refusal
        path, _, th = self.serve(b"")
        err = logban.ctl_drop(path)("2001:db8::1", 60)
        th.join()
        self.assertEqual(err, '"no reply"')
        self.assertNotIsInstance(err, logban.Refused)

    def test_no_daemon(self):
        err = logban.ctl_drop("/nonexistent/sock")("::2", 1)
        self.assertIsNotNone(err)
        self.assertNotIsInstance(err, logban.Refused)


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
        def of(path, ua):
            return judge.profile_of((path, ua, ""))

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


IOS = "t13d2014h2_a09f3c656075_14788d8d241b"
OKHTTP = "t13d1516h2_8daaf6152771_02713d6af862"
REQUESTS = "t13d1812h1_85036bcba153_b26ce05bbdd6"
CHROME_JA4 = "t13d1517h2_8daaf6152771_b1ff8ab2d16f"


def ja4_config():
    cfg = logban.Config()

    for k, v in (("costly", "^/api/"),
                 ("profile app", "ja4:^%s$" % IOS),
                 ("profile app", "ja4:^%s$" % OKHTTP),
                 ("app.ratio", "off"),
                 ("app.max_backend_seconds", "100"),
                 ("profile api_other", "path:^/api/"),
                 ("api_other.min_costly", "20")):
        cfg.set(k, v)

    cfg.check()
    return cfg


class Ja4Test(unittest.TestCase):

    def test_parse(self):
        r = logban.parse_line(line("::1", T0, "/", rt="0.1", ja4=OKHTTP))
        self.assertEqual(r[5], OKHTTP)
        self.assertEqual(r[3], 0.1)

        # no TLS, the module did not run, or no field at all
        for s in (line("::1", T0, "/", ja4="-"), line("::1", T0, "/", ja4=""),
                  line("::1", T0, "/")):
            self.assertEqual(logban.parse_line(s)[5], "")

        # ja4t= (the TCP fingerprint) is not ja4=
        s = line("::1", T0, "/").replace("\n", " ja4t=1024_2-4-8_1460_7\n")
        self.assertEqual(logban.parse_line(s)[5], "")

    def test_exact_and_regex(self):
        cfg = ja4_config()
        cfg.set("profile legacy", "ja4:^t12d")
        cfg.set("legacy.max_backend_seconds", "10")
        cfg.check()
        app, legacy = cfg.profiles[1], cfg.profiles[3]

        # exact fingerprints are a set, not regexes
        self.assertEqual(app.ja4, {IOS, OKHTTP})
        self.assertEqual(app.match, [])
        self.assertEqual(len(legacy.match), 1)

        judge = logban.Judge(cfg, Recorder(), out=io.StringIO())
        of = judge.profile_of
        self.assertEqual(of(("/api/x", "", OKHTTP)), 1)
        self.assertEqual(of(("/api/x", "", REQUESTS)), 2)
        self.assertEqual(of(("/api/x", "", "")), 2)
        self.assertEqual(of(("/", "", REQUESTS)), 0)
        self.assertEqual(of(("/", "", "t12d0909h1_x_y")), 3)
        # exact means exact
        self.assertEqual(of(("/", "", OKHTTP + "0")), 0)

    def test_known_stack_passes_unknown_banned(self):
        def calls(ip, ja4, n=60):
            return [line(ip, T0 + i * 0.5, "/api/search", rt="0.1",
                         urt="0.1", ua=APP, ja4=ja4) for i in range(n)]

        lines = merge(calls("198.51.100.1", IOS),
                      calls("198.51.100.2", OKHTTP),
                      # a script sending the app's user agent
                      calls("203.0.113.7", REQUESTS),
                      # plain HTTP, no fingerprint
                      calls("203.0.113.8", ""))
        act, out, _ = run(ja4_config(), lines)

        self.assertEqual(sorted(ip for ip, _ in act.calls),
                         ["203.0.113.7", "203.0.113.8"])
        self.assertIn("rule=api_other.ratio", out)

    def test_copied_fingerprint_still_limited(self):
        # utls or curl-impersonate copying the iOS stack: the app's
        # limits still apply
        lines = [line("203.0.113.9", T0 + i * 0.2, "/api/report", rt="1",
                      urt="1", ja4=IOS) for i in range(150)]
        act, out, _ = run(ja4_config(), lines)

        self.assertEqual(len(act.calls), 1)
        self.assertIn("rule=app.backend", out)

    def report(self, lines, n=10):
        out = io.StringIO()
        judge = logban.Judge(ja4_config(), Recorder(), out=out)
        judge.ja4s = {}

        for s in lines:
            judge.feed(s)

        judge.finish()
        judge.report_ja4(n)
        return judge, out.getvalue()

    def test_top_ja4(self):
        lines = merge(
            [line("198.51.100.%d" % k, T0 + k, "/api/x", rt="0.1",
                  urt="0.1", ua=APP, ja4=IOS) for k in range(1, 7)],
            [line("198.51.100.9", T0 + k, "/api/x", ua="okhttp/4.12.0",
                  ja4=OKHTTP) for k in range(3)],
            [line("203.0.113.7", T0 + k * 0.1, "/api/x",
                  ua="python-requests/2.31", ja4=REQUESTS)
             for k in range(100)],
            [line("192.0.2.1", T0, "/")])
        judge, out = self.report(lines)
        rows = out[out.index("\n  1  "):].splitlines()[1:]

        self.assertRegex(rows[0], r"^  1  %s +100 +90\.9%% +1 +1 " % REQUESTS)
        self.assertIn("100% python-requests/2.31", rows[0])
        self.assertRegex(rows[1], r"^  2  %s +6 +5\.5%% +6 +0 +0\.6" % IOS)
        self.assertRegex(rows[2], r"^  3  %s +3 " % OKHTTP)
        self.assertRegex(rows[3], r"^  4  \(none\) +1 ")
        # commented out, with what this run banned
        self.assertIn("# profile app = ja4:^%s$    # 0 banned, %s"
                      % (IOS, APP), out)
        self.assertIn("# profile app = ja4:^%s$    # 1 banned, python"
                      % REQUESTS, out)
        self.assertNotIn("ja4:^$", out)

        # uncommented, the lines load as a config
        cfg = logban.Config()
        cfg.set("costly", "x")

        for ln in out.splitlines():
            if ln.startswith("# profile "):
                k, _, v = ln[2:].split("#")[0].partition("=")
                cfg.set(k.strip(), v.strip())

        cfg.set("app.max_backend_seconds", "100")
        cfg.check()
        self.assertEqual(cfg.profiles[1].ja4, {IOS, OKHTTP, REQUESTS})

    def test_top_ja4_no_field(self):
        _, out = self.report([line("198.51.100.1", T0, "/")])
        self.assertIn("(no ja4= in the log)", out)

    def test_off_by_default(self):
        _, _, judge = run(ja4_config(), [line("::2", T0, "/", ja4=IOS)])
        self.assertIsNone(judge.ja4s)


HONEY = r"^/(wp-login\.php|xmlrpc\.php|\.env|\.git(/|$))"


class HoneyTest(unittest.TestCase):

    def test_first_hit_bans_now(self):
        # one probe among browsing; the ban is stamped with the probe's
        # time, not the next step
        lines = merge(browser("198.51.100.9", n=20),
                      [line("203.0.113.7", T0 + 3.5, "/.env")])
        act, out, judge = run(config(honey=[HONEY]), lines)

        self.assertEqual(act.calls, [("203.0.113.7", 3600)])
        self.assertIn("2026-10-03T10:00:03Z ban 203.0.113.7 ttl=3600"
                      " offense=1", out)
        self.assertIn("rule=honey path=/.env\n", out)
        self.assertEqual(judge.honey_hits, 1)
        # not counted in the window or the path report
        self.assertNotIn("/.env", judge.paths)
        self.assertNotIn(("203.0.113.7", 0), judge.win.totals)

    def test_paths(self):
        cfg = config(honey=[HONEY])
        # /.envrc too: nobody serves it to visitors either
        hits = ["/.env", "/.env.local", "/.envrc", "/.git", "/.git/config",
                "/wp-login.php", "/xmlrpc.php?rsd"]
        misses = ["/", "/.github/x", "/blog/wp-login.php",
                  "/search?q=/.env"]

        for path in hits + misses:
            act, _, _ = run(cfg, [line("203.0.113.7", T0, path)])
            self.assertEqual(len(act.calls), path in hits, path)

    def test_one_ban_per_ttl(self):
        lines = [line("203.0.113.7", T0 + i, p) for i, p in
                 enumerate(["/.env", "/.git/config", "/wp-login.php"])]
        act, _, judge = run(config(honey=[HONEY]), lines)
        self.assertEqual(len(act.calls), 1)
        self.assertEqual(judge.honey_hits, 3)

    def test_escalates_and_caps(self):
        # each probe after the last ban has ended
        lines = [line("203.0.113.7", T0 + k * 20000, "/.env")
                 for k in range(4)]
        act, _, _ = run(config(honey=[HONEY], honey_ttl=3600,
                               max_ttl=10000), lines)
        self.assertEqual([t for _, t in act.calls],
                         [3600, 7200, 10000, 10000])

    def test_shares_offenses_with_rules(self):
        # banned by the ratio rule first: a later probe is offense 2
        lines = bot("203.0.113.7") + [line("203.0.113.7", T0 + 3600,
                                           "/.env")]
        act, out, _ = run(config(honey=[HONEY]), lines)
        self.assertEqual(act.calls, [("203.0.113.7", 600),
                                     ("203.0.113.7", 7200)])

    def test_exempt(self):
        dns = {"66.249.66.1": (["crawl.googlebot.com"], set()),
               "crawl.googlebot.com": ([], {"66.249.66.1"})}
        lines = [line("192.0.2.1", T0, "/.env"),
                 line("127.0.0.1", T0, "/.env"),
                 line("66.249.66.1", T0, "/.env"),
                 line("-", T0, "/.env")]
        act, _, judge = run(config(honey=[HONEY], allow=["192.0.2.0/24"],
                                   crawler=["googlebot.com"]), lines,
                            resolve=lambda n: dns.get(n, ([], set())))
        self.assertEqual(act.calls, [])
        self.assertEqual(judge.honey_hits, 4)

    def test_wins_over_skip(self):
        act, _, _ = run(config(honey=[HONEY], skip=["^/\\."]),
                        [line("203.0.113.7", T0, "/.env")])
        self.assertEqual(len(act.calls), 1)

    def test_failed_ban_retried_by_next_probe(self):
        act = Recorder(fail='"connect: No such file"')
        lines = [line("203.0.113.7", T0 + i, "/.env") for i in range(3)]
        _, out, _ = run(config(honey=[HONEY]), lines, act=act)
        self.assertEqual(len(act.calls), 3)
        self.assertEqual(out.count("error="), 3)

    def test_review(self):
        judge = logban.Judge(config(honey=[HONEY]), logban.dry_run,
                             out=io.StringIO())
        judge.history = []

        for s in merge(bot("203.0.113.8"),
                       [line("203.0.113.7", T0, "/.git/config")]):
            judge.feed(s)

        judge.finish()
        rows = logban.summarize(judge.history)
        self.assertEqual({r["ip"]: r["rules"] for r in rows},
                         {"203.0.113.7": {"honey"},
                          "203.0.113.8": {"ratio"}})

    def test_config(self):
        cfg = ConfigTest.load(self, "honey = %s\nhoney = ^/phpmyadmin\n"
                                    "costly = x\n" % HONEY)
        self.assertEqual(len(cfg.honey), 2)
        self.assertEqual(cfg.honey_ttl, 3600)

        for text in ("honey = .\n",               # matches /
                     "honey = php|\n",            # matches the empty path
                     "honey = ^/(\n",             # bad regex
                     "honey = ^/x\nhoney_ttl = 0\n",
                     "honey = ^/x\nhoney_ttl = 90000\n"):   # > max_ttl
            with self.assertRaises(logban.ConfigError, msg=text):
                ConfigTest.load(self, "costly = x\n" + text)

        # honey_ttl is only checked when there are honey paths
        cfg = ConfigTest.load(self, "costly = x\nmax_ttl = 600\n")
        self.assertEqual(cfg.honey, [])


def watch_config(*lines):
    cfg = logban.Config()

    for ln in ("costly = ^/search",) + lines:
        k, _, v = ln.partition("=")
        cfg.set(k.strip(), v.strip())

    cfg.check()
    return cfg


SCAN = ("watch scan = status:404", "scan.max = 50")
LOGIN = ("watch login = method:POST path:^/login$ status:401|403",
         "login.max = 20")
THROTTLED = ("watch throttled = status:429", "throttled.max = 30")


def hits(ip, n, path="/x", every=0.5, start=T0, **kw):
    return [line(ip, start + i * every, path, **kw) for i in range(n)]


class WatchTest(unittest.TestCase):

    def test_parse(self):
        r = logban.parse_line(line("::1", T0, "/login?next=/", method="POST",
                                   status=401))
        self.assertEqual((r[logban.F_METHOD], r[logban.F_PATH],
                          r[logban.F_STATUS]), ("POST", "/login", "401"))

        s = ('198.51.100.1 - - [03/Oct/2026:10:00:00 +0000] "\\x16\\x03"'
             ' 400 0 "-" "-"\n')
        r = logban.parse_line(s)
        self.assertEqual(r[6:], ("", "400"))
        self.assertEqual(r[logban.F_PATH], "")

    def test_scan(self):
        act, out, _ = run(watch_config(*SCAN), hits("203.0.113.7", 60,
                                                    status=404))
        self.assertEqual(act.calls, [("203.0.113.7", 600)])
        # hits as counted at the judgment step
        self.assertIn("total=60 costly=0 ratio=0.00 backend=0.0s rule=scan"
                      " hits=60\n", out)

        act, _, _ = run(watch_config(*SCAN), hits("203.0.113.7", 49,
                                                  status=404))
        self.assertEqual(act.calls, [])

    def test_window_slides(self):
        # 100 404s over 10 minutes: never 50 in 60 s
        act, _, _ = run(watch_config(*SCAN), hits("203.0.113.7", 100,
                                                  every=6, status=404))
        self.assertEqual(act.calls, [])

    def test_ratio(self):
        # a NAT: 60 404s (missing images) among 600 pages
        lines = merge(hits("100.64.0.1", 60, every=0.5, status=404),
                      hits("100.64.0.1", 540, path="/", every=0.05))
        act, _, _ = run(watch_config(*SCAN), lines)
        self.assertEqual(len(act.calls), 1)

        act, _, _ = run(watch_config(*SCAN, "scan.ratio = 0.5"), lines)
        self.assertEqual(act.calls, [])

        # a scanner: almost only 404s
        lines = merge(hits("203.0.113.7", 60, status=404),
                      hits("203.0.113.7", 5, path="/"))
        act, out, _ = run(watch_config(*SCAN, "scan.ratio = 0.5"), lines)
        self.assertEqual(len(act.calls), 1)
        self.assertIn("total=65 ", out)
        self.assertIn("rule=scan hits=60\n", out)

    def test_login(self):
        cfg = watch_config(*LOGIN)

        act, out, _ = run(cfg, hits("203.0.113.7", 25, path="/login",
                                    method="POST", status=401))
        self.assertEqual(len(act.calls), 1)
        self.assertRegex(out, r"rule=login hits=2\d\n")

        # 403 counts too; GET, a 200, or another path do not
        lines = (hits("203.0.113.8", 20, path="/login", method="POST",
                      status=403))
        self.assertEqual(len(run(cfg, lines)[0].calls), 1)

        for kw in ({"method": "GET", "status": 401},
                   {"method": "POST", "status": 200},
                   {"method": "POST", "status": 422}):
            lines = hits("203.0.113.9", 30, path="/login", **kw)
            self.assertEqual(run(cfg, lines)[0].calls, [], kw)

        lines = hits("203.0.113.9", 30, path="/login/help", method="POST",
                     status=401)
        self.assertEqual(run(cfg, lines)[0].calls, [])

    def test_throttled(self):
        # nginx limit_req answering 429: escalate to XDP
        act, out, _ = run(watch_config(*THROTTLED),
                          hits("203.0.113.7", 40, status=429))
        self.assertEqual(len(act.calls), 1)
        self.assertIn("rule=throttled", out)

    def test_or_lines_and_regex(self):
        cfg = watch_config("watch errors = status:5..",
                           "watch errors = path:^/cgi-bin/",
                           "errors.max = 10", "errors.ttl = 120")
        lines = merge(hits("203.0.113.7", 5, status=502),
                      hits("203.0.113.7", 5, path="/cgi-bin/x", start=T0 + 1))
        act, _, _ = run(cfg, lines)
        self.assertEqual(act.calls, [("203.0.113.7", 120)])

    def test_not_counted(self):
        # allowlisted and skipped requests never reach a watch
        cfg = watch_config(*SCAN, "allow = 192.0.2.0/24", "skip = ^/static/")
        lines = merge(hits("192.0.2.1", 60, status=404),
                      hits("203.0.113.7", 60, path="/static/a.png",
                           status=404))
        act, _, judge = run(cfg, lines)
        self.assertEqual(act.calls, [])
        self.assertEqual(judge.watched.totals, {})

    def test_crawler_exempt(self):
        dns = {"66.249.66.1": (["crawl.googlebot.com"], set()),
               "crawl.googlebot.com": ([], {"66.249.66.1"})}
        cfg = watch_config(*SCAN, "crawler = googlebot.com")
        act, _, _ = run(cfg, hits("66.249.66.1", 60, status=404),
                        resolve=lambda n: dns.get(n, ([], set())))
        self.assertEqual(act.calls, [])

    def test_one_ban_clears_all(self):
        # a scanner that also floods: one ban, every counter cleared
        cfg = watch_config(*SCAN, *THROTTLED)
        lines = merge(hits("203.0.113.7", 50, path="/search", every=0.4),
                      hits("203.0.113.7", 50, status=404, every=0.4),
                      hits("203.0.113.7", 30, status=429, every=0.4))
        act, _, judge = run(cfg, lines)
        self.assertEqual(len(act.calls), 1)
        self.assertEqual(judge.win.totals, {})
        self.assertEqual(judge.watched.totals, {})

    def test_refused_held(self):
        act = Recorder(fail=logban.Refused('"error: refused"'))
        run(watch_config(*SCAN), hits("198.51.100.10", 600, every=0.2,
                                      status=404), act=act)
        self.assertEqual(len(act.calls), 1)

    def test_config(self):
        cfg = watch_config(*SCAN, *LOGIN, "scan.ratio = 0.5",
                           "login.ttl = 3600")
        scan, login = cfg.watches
        self.assertEqual((scan.max, scan.ratio, scan.ttl), (50, 0.5, 600))
        self.assertEqual((login.max, login.ratio, login.ttl), (20, None, 3600))
        self.assertEqual(len(login.alts[0]), 3)

        # watches alone, or honey alone, are a working config
        ConfigTest.load(self, "watch scan = status:404\nscan.max = 9\n")
        ConfigTest.load(self, "honey = ^/\\.env\n")

    def test_key_whitespace(self):
        # the type and the name may be split by any run of whitespace
        for key in ("watch scan", "watch   scan", "watch\tscan",
                    "watch \t scan"):
            cfg = ConfigTest.load(self, "costly = x\n%s = status:404\n"
                                        "scan.max = 5\n" % key)
            self.assertEqual([w.name for w in cfg.watches], ["scan"], key)

        cfg = ConfigTest.load(self, "costly = x\nprofile\tapi = ua:x\n"
                                    "api.ratio = 0.5\n")
        self.assertEqual(cfg.profiles[1].name, "api")

        for key in ("watchscan", "watch", "watch scan two", "Watch scan"):
            with self.assertRaises(logban.ConfigError, msg=key):
                ConfigTest.load(self, "costly = x\n%s = status:404\n"
                                      "scan.max = 5\n" % key)

    def test_config_errors(self):
        for text in ("watch scan = status:404\n",                 # no max
                     "watch scan = status:404\nscan.max = 0\n",
                     "watch scan = code:404\nscan.max = 5\n",
                     "watch scan = status\nscan.max = 5\n",
                     "watch scan = status:(\nscan.max = 5\n",
                     "watch honey = status:404\nhoney.max = 5\n",
                     "watch cluster = status:404\ncluster.max = 5\n",
                     "watch Scan = status:404\n",
                     "scan.max = 5\n",                             # undeclared
                     "watch scan = status:404\nscan.max = 5\n"
                     "scan.min_costly = 5\n",                    # profile key
                     "profile api = ua:x\napi.max_backend_seconds = 5\n"
                     "api.max = 5\n",                             # watch key
                     "profile x = ua:x\nx.max_backend_seconds = 5\n"
                     "watch x = status:404\nx.max = 5\n",        # both
                     "watch scan = status:404\nscan.max = 5\n"
                     "scan.ttl = 999999\n",
                     "watch scan = status:404\nscan.max = 5\n"
                     "scan.ratio = 2\n"):
            with self.assertRaises(logban.ConfigError, msg=text):
                ConfigTest.load(self, "costly = x\n" + text)


class ExplainTest(unittest.TestCase):

    def explain(self, ip, lines, cfg=None, resolve=None):
        cfg = cfg or config()
        out = io.StringIO()
        act = Recorder()
        judge = logban.Judge(cfg, act, out=io.StringIO(), resolve=resolve)
        judge.explain = logban.Explain(ip, judge, out)

        for s in lines:
            judge.feed(s)

        judge.finish()
        judge.explain.summary()
        return out.getvalue(), judge

    def test_bot(self):
        text, _ = self.explain("203.0.113.7", merge(
            bot("203.0.113.7", n=1500), browser("198.51.100.9")))
        rows = text.splitlines()

        self.assertIn("explain 203.0.113.7: 60 s window, judged every 10 s",
                      rows[0])
        self.assertIn("10:00:10  default      total=50 costly=50"
                      " backend=0.0s  under: costly 50 < min_costly 100",
                      rows[1])
        self.assertIn("10:00:20  default      total=100 costly=100", rows[2])
        self.assertTrue(rows[2].endswith("fires ratio"))
        self.assertIn("10:00:20  BAN          rule=ratio ttl=600 offense=1,"
                      " until 2026-10-03 10:10:20", rows[3])
        # the replay keeps sending while banned: one line, not 59
        self.assertRegex(rows[4], r"banned +\d+ steps not shown")
        self.assertIn("bans: ratio at 2026-10-03 10:00:20, ttl 600", text)
        # nothing about the browser
        self.assertNotIn("198.51.100.9", text)

    def test_matches_a_normal_run(self):
        lines = merge(bot("203.0.113.7", n=3000), bot("203.0.113.8"),
                      browser("198.51.100.9"))
        act, out, _ = run(config(), lines)
        _, judge = self.explain("203.0.113.7", lines)
        normal = [l for l in out.splitlines() if " 203.0.113.7 " in l]
        self.assertEqual(len(judge.explain.bans), len(normal))

        for (t, rule, ttl), l in zip(judge.explain.bans, normal):
            self.assertIn("ban 203.0.113.7 ttl=%d " % ttl, l)
            self.assertIn("rule=" + rule, l)
            self.assertTrue(l.startswith(time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))))

    def test_under_reasons(self):
        # 150 costly + 30 cheap: enough costly, too small a share
        lines = merge(bot("203.0.113.7", n=150),
                      bot("203.0.113.7", n=30, path="/", start=T0 + 0.1))
        text, _ = self.explain("203.0.113.7", lines,
                               config(max_backend_seconds=500))
        self.assertIn("under: costly share 0.83 < ratio 0.90;"
                      " backend 0.0 s < 500.0 s", text)
        self.assertIn("bans: none", text)

    def test_never_judged(self):
        text, _ = self.explain("192.0.2.1", bot("192.0.2.1"),
                               config(allow=["192.0.2.0/24"]))
        self.assertEqual(text.count("never judged"), 2)    # row, summary
        self.assertIn("allowlisted (allow or allow_file): no rule", text)
        self.assertIn("judged 0;", text)

    def test_crawler(self):
        dns = {"66.249.66.1": (["crawl.googlebot.com"], set()),
               "crawl.googlebot.com": ([], {"66.249.66.1"})}
        text, _ = self.explain("66.249.66.1", bot("66.249.66.1"),
                               config(crawler=["googlebot.com"]),
                               resolve=lambda n: dns.get(n, ([], set())))
        self.assertIn("fires ratio, exempt: crawler", text)
        self.assertIn("bans: none", text)

    def test_honey_skip_profiles_watches(self):
        cfg = watch_config(*SCAN, "scan.ratio = 0.5", "honey = ^/\\.env",
                           "skip = ^/static/", "profile api = path:^/api/",
                           "api.max_backend_seconds = 100")
        lines = merge(hits("203.0.113.7", 40, status=404, every=0.25),
                      hits("203.0.113.7", 40, path="/api/x", every=0.25),
                      hits("203.0.113.7", 5, path="/static/a.css"),
                      [line("203.0.113.7", T0 + 25, "/.env")])
        text, _ = self.explain("203.0.113.7", lines, cfg)

        self.assertIn("default      total=40 costly=0", text)
        self.assertIn("api          total=40 costly=0", text)
        self.assertIn("watch scan   hits=40 of 80  under: hits 40 < max 50",
                      text)
        self.assertIn("honey        /.env", text)
        self.assertIn("BAN          rule=honey ttl=3600", text)
        self.assertIn("judged default 40, api 40; skipped 5; honey 1", text)

    def test_watch_ratio(self):
        cfg = watch_config(*SCAN, "scan.ratio = 0.5")
        lines = merge(hits("100.64.0.1", 60, status=404),
                      hits("100.64.0.1", 540, path="/", every=0.05))
        text, _ = self.explain("100.64.0.1", lines, cfg)
        self.assertRegex(text, r"watch scan +hits=\d+ of \d+  under: hits"
                               r" share 0\.\d\d < ratio 0\.50")

    def test_not_in_log(self):
        text, _ = self.explain("9.9.9.9", bot("203.0.113.7", n=5))
        self.assertIn("9.9.9.9 is not in the log", text)

    def main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        saved = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err

        try:
            code = logban.main(list(argv))

        finally:
            sys.stdout, sys.stderr = saved

        return code, out.getvalue(), err.getvalue()

    def test_cli(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "access.log")
        conf = os.path.join(d, "logban.conf")

        with open(log, "w") as f:
            f.writelines(bot("2001:db8::bad"))

        with open(conf, "w") as f:
            # a socket that does not exist: --explain must not use it
            f.write("costly = ^/search\nsocket = %s/none.sock\n" % d)

        code, out, _ = self.main("-c", conf, "-x", "2001:DB8:0::BAD", log)
        self.assertEqual(code, 0)
        self.assertIn("explain 2001:db8::bad:", out)
        self.assertIn("BAN          rule=ratio", out)
        self.assertNotIn("error", out)

        for argv, msg in ((["-x", "300.1.1.1"], "not an address"),
                          (["-x", "::1", "-f"], "not with -f"),
                          (["-x", "::1", "-r"], "not with -f or --review")):
            code, _, err = self.main("-c", conf, *argv, log)
            self.assertEqual(code, 1)
            self.assertIn(msg, err)


BOT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0"


def cluster_config(*extra):
    return watch_config("costly = ^/api/", "cluster_min_addresses = 10",
                        "cluster_min_costly = 100", *extra)


def botnet(n=30, per=10, start=T0, ua=BOT_UA, ja4=REQUESTS, path="/search",
           net="203.0.113.%d"):
    """n addresses, each sending per costly requests over 50 s: far
    under any per-address threshold."""

    return merge(*[[line(net % (k + 1), start + i * 50 / per + k * 0.01,
                         path, ua=ua, ja4=ja4) for i in range(per)]
                   for k in range(n)])


class ClusterTest(unittest.TestCase):

    def test_wide_botnet(self):
        lines = botnet()

        act, _, _ = run(config(), lines)
        self.assertEqual(act.calls, [], "per-address rules see nothing")

        act, out, _ = run(cluster_config(), lines)
        self.assertEqual(sorted(ip for ip, _ in act.calls),
                         sorted("203.0.113.%d" % (k + 1) for k in range(30)))
        self.assertIn('rule=cluster cluster=30 ja4=%s ua="%s"\n'
                      % (REQUESTS, BOT_UA), out)

    def test_ua_alone(self):
        # no ja4= in the log: the user agent is the fingerprint
        lines = [ln.replace(" ja4=" + REQUESTS, "") for ln in botnet()]
        act, out, _ = run(cluster_config(), lines)
        self.assertEqual(len(act.calls), 30)
        self.assertIn('rule=cluster cluster=30 ua="', out)
        self.assertNotIn("ja4=", out)

    def test_browsers_share_a_fingerprint(self):
        # 50 real browsers on one stack: plenty of costly requests, but
        # mostly cheap pages and assets
        lines = merge(*[[line("198.51.100.%d" % (k + 1), T0 + i + k * 0.01,
                              "/search" if i % 4 == 0 else "/", ua=BOT_UA,
                              ja4=CHROME_JA4) for i in range(40)]
                        for k in range(50)])
        act, _, judge = run(cluster_config(), lines)
        self.assertEqual(act.calls, [])

    def test_search_only_users_in_a_browser_cluster(self):
        # 50 browsing normally, 5 who only ran a few searches: each of
        # the 5 looks like a bot alone, the cluster shows they are not
        lines = merge(*[[line("198.51.100.%d" % (k + 1), T0 + i + k * 0.01,
                              "/search" if i % 4 == 0 else "/", ua=BOT_UA,
                              ja4=CHROME_JA4) for i in range(40)]
                        for k in range(50)],
                      *[[line("198.51.101.%d" % (k + 1), T0 + i * 5,
                              "/search", ua=BOT_UA, ja4=CHROME_JA4)
                         for i in range(4)] for k in range(5)])
        act, _, _ = run(cluster_config(), lines)
        self.assertEqual(act.calls, [])

    def test_members_must_behave_like_bots(self):
        lines = merge(
            botnet(),
            # shares the fingerprint, browses normally
            [line("192.0.2.200", T0 + i, "/search" if i % 3 == 0 else "/",
                  ua=BOT_UA, ja4=REQUESTS) for i in range(30)],
            # shares it, two costly requests only
            [line("192.0.2.201", T0 + i, "/search", ua=BOT_UA, ja4=REQUESTS)
             for i in range(2)])
        act, _, _ = run(cluster_config(), lines)
        banned = {ip for ip, _ in act.calls}
        self.assertEqual(len(banned), 30)
        self.assertNotIn("192.0.2.200", banned)
        self.assertNotIn("192.0.2.201", banned)

    def test_thresholds(self):
        # 9 addresses, or 99 costly requests: no cluster
        act, _, _ = run(cluster_config(), botnet(n=9, per=20))
        self.assertEqual(act.calls, [])
        act, _, _ = run(cluster_config(), botnet(n=11, per=9))
        self.assertEqual(act.calls, [])
        # the same 300 requests spread over 10 minutes: no window holds
        lines = merge(*[[line("203.0.113.%d" % (k + 1), T0 + i * 60 + k,
                              "/search", ua=BOT_UA, ja4=REQUESTS)
                         for i in range(10)] for k in range(30)])
        act, _, _ = run(cluster_config(), lines)
        self.assertEqual(act.calls, [])

    def test_ratio_off_profiles_left_out(self):
        # an app's users: all costly by design, one fingerprint
        cfg = cluster_config("profile app = ua:^MyShop/", "app.ratio = off",
                             "app.max_backend_seconds = 100")
        lines = botnet(ua=APP, ja4=IOS, path="/api/search")
        act, _, judge = run(cfg, lines)
        self.assertEqual(act.calls, [])
        self.assertEqual(judge.clusters.totals, {})

    def test_exempt(self):
        # allowlisted members never counted; verified crawlers not banned
        lines = botnet(net="192.0.2.%d")
        act, _, judge = run(cluster_config("allow = 192.0.2.0/24"), lines)
        self.assertEqual((act.calls, judge.clusters.totals), ([], {}))

        def dns(n):
            if n.startswith("66.249.66."):
                return ["crawl-%s.googlebot.com" % n], set()

            if n.endswith(".googlebot.com"):
                return [], {n[6:-14]}

            return [], set()

        lines = botnet(net="66.249.66.%d", ua="Googlebot/2.1")
        act, _, _ = run(cluster_config("crawler = googlebot.com"), lines,
                        resolve=dns)
        self.assertEqual(act.calls, [])

    def test_off_by_default(self):
        _, _, judge = run(config(), botnet())
        self.assertIsNone(judge.clusters)

    def test_explain(self):
        lines = merge(botnet(), [line("192.0.2.200", T0 + i,
                                      "/search" if i % 3 == 0 else "/",
                                      ua=BOT_UA, ja4=REQUESTS)
                                 for i in range(30)])
        text, _ = ExplainTest.explain(self, "192.0.2.200", lines,
                                      cluster_config())
        self.assertRegex(text, r"cluster +addresses=31 costly=\d+/\d+, its"
                               r" \d+/\d+  under: its costly share 0\.\d+ <"
                               r" cluster_ratio 0\.90")

        text, _ = ExplainTest.explain(self, "203.0.113.1", lines,
                                      cluster_config())
        self.assertIn("under: cluster costly", text)
        self.assertRegex(text, r"cluster +addresses=31 .*  fires cluster\n")
        self.assertIn("BAN          rule=cluster", text)

    def test_config(self):
        for text in ("cluster_min_addresses = 1\n",
                     "cluster_min_addresses = 5\ncluster_ratio = 0\n",
                     "cluster_min_addresses = 5\ncluster_ratio = 1.5\n",
                     "cluster_min_addresses = 5\ncluster_min_costly = 0\n",
                     "cluster_min_addresses = 5\ncluster_member_min = 0\n"):
            with self.assertRaises(logban.ConfigError, msg=text):
                ConfigTest.load(self, "costly = x\n" + text)

        # bounds are only checked when clusters are on
        ConfigTest.load(self, "costly = x\ncluster_ratio = 5\n")


def jline(ip, t, path, method="GET", status=200, ua="Mozilla/5.0",
          rt=0.1, urt=0.1, **extra):
    """The same request as line(), the way log_format escape=json writes
    it (numbers as numbers, like the sample in data/)."""

    d = {"time_local": datetime.fromtimestamp(t, timezone.utc).strftime(
             "%d/%b/%Y:%H:%M:%S +0000"),
         "remote_addr": ip, "remote_user": "-",
         "request": "%s %s HTTP/1.1" % (method, path), "status": status,
         "body_bytes_sent": 512, "http_referer": "-",
         "http_user_agent": ua, "request_time": rt,
         "upstream_response_time": urt}
    d.update(extra)
    return json.dumps(d) + "\n"


class JsonTest(unittest.TestCase):

    def test_same_as_combined(self):
        for kw in ({"ip": "203.0.113.7", "t": T0, "path": "/search?q=1"},
                   {"ip": "2001:db8::7", "t": T0 + 1, "path": "/login",
                    "method": "POST", "status": 401},
                   {"ip": "198.51.100.1", "t": T0 + 2, "path": "/",
                    "status": 404, "ua": "curl/8"}):
            c = logban.parse_line(line(rt="0.1", urt="0.1", **kw))
            j = logban.parse_line(jline(**kw))
            self.assertEqual(j, c)

    def test_values(self):
        r = logban.parse_line(jline("::1", T0, "/x", rt=0.9,
                                    urt="0.5, 0.25 : 0.125"))
        self.assertEqual(r[logban.F_COST], 0.875)
        # urt "-" (nginx answered itself): rt; both absent: None
        self.assertEqual(logban.parse_line(jline("::1", T0, "/", rt=0.002,
                                                 urt="-"))[3], 0.002)
        d = json.loads(jline("::1", T0, "/"))
        del d["request_time"], d["upstream_response_time"]
        self.assertIsNone(logban.parse_line(json.dumps(d))[3])
        # ja4 from either name; "-" is none
        self.assertEqual(logban.parse_line(jline("::1", T0, "/",
                                                 ja4=IOS))[5], IOS)
        self.assertEqual(logban.parse_line(jline("::1", T0, "/",
                                                 http_ssl_ja4=IOS))[5], IOS)
        self.assertEqual(logban.parse_line(jline("::1", T0, "/",
                                                 ja4="-"))[5], "")

    def test_time_fields(self):
        d = json.loads(jline("::1", T0, "/"))
        del d["time_local"]

        for extra in ({"time_iso8601": "2026-10-03T10:00:00+00:00"},
                      {"time_iso8601": "2026-10-03T18:00:00+08:00"},
                      {"msec": "%.3f" % T0}, {"msec": T0}):
            r = logban.parse_line(json.dumps(dict(d, **extra)))
            self.assertEqual(r[1], T0, extra)

        self.assertIsNone(logban.parse_line(json.dumps(d)))

    def test_method_and_uri(self):
        d = json.loads(jline("::1", T0, "/"))
        del d["request"]
        d.update(request_method="POST", request_uri="/login?next=/")
        r = logban.parse_line(json.dumps(d))
        self.assertEqual((r[6], r[2]), ("POST", "/login"))

    def test_unparsed(self):
        for bad in ('{"remote_addr": "::1"\n',            # cut short
                    '{"time_local": "03/Oct/2026:10:00:00 +0000"}\n',
                    '{"remote_addr": "::1", "time_local": "yesterday"}\n',
                    '{"remote_addr": "::1", "time_local": [1]}\n',
                    '{"remote_addr": "::1", "msec": "x"}\n'):
            self.assertIsNone(logban.parse_line(bad), bad)

    def test_custom_fields(self):
        # behind realip: the peer is in realip_remote_addr
        cfg = config()
        cfg.set("json_ip", "realip_remote_addr")
        cfg.set("json_ua", "ua, http_user_agent")
        cfg.check()
        s = jline("198.51.100.9", T0, "/", realip_remote_addr="203.0.113.7",
                  ua="custom")
        r = logban.parse_line(s, cfg.json_fields)
        self.assertEqual((r[0], r[4]), ("203.0.113.7", "custom"))

        with self.assertRaises(logban.ConfigError):
            ConfigTest.load(self, "costly = x\njson_ip = remote_addr,\n")

    def test_same_bans(self):
        # one replay in each format, and both mixed in one file
        cfg = watch_config(*SCAN, "honey = ^/\\.env")
        reqs = ([dict(ip="203.0.113.7", t=T0 + i * 0.2, path="/search")
                 for i in range(150)]
                + [dict(ip="203.0.113.8", t=T0 + i * 0.3, path="/x%d" % i,
                        status=404) for i in range(60)]
                + [dict(ip="203.0.113.9", t=T0 + 5, path="/.env")]
                + [dict(ip="198.51.100.1", t=T0 + i, path="/")
                   for i in range(50)])
        reqs.sort(key=lambda r: r["t"])
        c = run(cfg, [line(rt="0.1", urt="0.1", **r) for r in reqs])[1]
        j = run(cfg, [jline(**r) for r in reqs])[1]
        m = run(cfg, [jline(**r) if i % 2 else line(rt="0.1", urt="0.1", **r)
                      for i, r in enumerate(reqs)])[1]
        self.assertEqual(c.count(" ban "), 3)
        self.assertEqual(j, c)
        self.assertEqual(m.count(" ban "), 3)

    def test_sample_in_data(self):
        # the sample shipped in data/: every line parses
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "data", "clickHouse.access.log")

        if not os.path.exists(path):
            self.skipTest("no data/clickHouse.access.log")

        with open(path) as f:
            lines = f.readlines()

        self.assertTrue(all(logban.parse_line(l) for l in lines))


class TimeTest(unittest.TestCase):

    def test_fast_path_matches_strptime(self):
        for s in ("03/Oct/2026:10:00:00 +0000", "29/Feb/2028:23:59:59 -0700",
                  "01/Jan/1970:00:00:00 +0530", "31/Dec/2037:12:00:00 +1400"):
            self.assertEqual(logban.parse_time_local(s), datetime.strptime(
                s, "%d/%b/%Y:%H:%M:%S %z").timestamp(), s)

    def test_rejects(self):
        for s in ("32/Oct/2026:10:00:00 +0000", "03/Foo/2026:10:00:00 +0000",
                  "03/Oct/2026:24:00:00 +0000", "03/Oct/2026 10:00:00 +0000",
                  ""):
            with self.assertRaises(ValueError, msg=s):
                logban.parse_time_local(s)


# Cloudflare's ranges on 2026-10-04 (api.cloudflare.com/client/v4/ips),
# fixed so the replay below needs no network.
CLOUDFLARE = """103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 104.16.0.0/13
104.24.0.0/14 108.162.192.0/18 131.0.72.0/22 141.101.64.0/18 162.158.0.0/15
172.64.0.0/13 173.245.48.0/20 188.114.96.0/20 190.93.240.0/20 197.234.240.0/22
198.41.128.0/17 2400:cb00::/32 2405:8100::/32 2405:b500::/32 2606:4700::/32
2803:f800::/32 2a06:98c0::/29 2c0f:f248::/32""".split()

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


class DataTest(unittest.TestCase):
    """Replays of the logs in data/: guards the results in doc/logban.md
    section 17 against later changes."""

    def setUp(self):
        if not os.path.exists(os.path.join(DATA, "me.access.log")):
            self.skipTest("no data/")

    def replay(self, conf_text, log):
        d = tempfile.mkdtemp()
        cdn = os.path.join(d, "cdn.txt")
        conf = os.path.join(d, "me.conf")

        with open(cdn, "w") as f:
            f.write("\n".join(CLOUDFLARE) + "\n")

        with open(conf, "w") as f:
            f.write(conf_text.replace("/etc/logban/cdn-allow.txt", cdn))

        cfg = logban.Config()
        cfg.load(conf)
        # no DNS in tests: as in the real replay, no crawler verifies
        judge = logban.Judge(cfg, logban.dry_run, out=io.StringIO(),
                             resolve=lambda n: ([], set()))
        judge.history = []
        dropped = 0

        with open(os.path.join(DATA, log), errors="replace") as f:
            lines = f.readlines()

        for s in lines:
            r = logban.parse_line(s, cfg.json_fields)

            if r and judge.banned.get(r[0], 0) > r[1]:
                dropped += 1

            judge.feed(s)

        judge.finish()
        return judge, lines, dropped

    def test_me(self):
        with open(os.path.join(DATA, "me.conf")) as f:
            judge, lines, dropped = self.replay(f.read(), "me.access.log")

        banned = {b[1] for b in judge.history}
        nets = [logban.ipaddress.ip_network(n) for n in CLOUDFLARE]
        players = set()

        for s in lines:
            r = logban.parse_line(s)

            if r and r[2].endswith((".js", ".css")) and r[7][0] in "23":
                players.add(r[0])

        self.assertEqual(len(banned), 261)
        self.assertEqual({b[6] for b in judge.history}, {"honey"})
        self.assertFalse([ip for ip in banned if any(
            logban.ipaddress.ip_address(ip) in n for n in nets)],
            "Cloudflare edges banned")
        self.assertEqual(banned & players, set(), "players banned")
        self.assertIn("213.209.159.175", banned)
        self.assertGreater(dropped / len(lines), 0.70)

        # banned before it downloaded .git (20 Sep 01:52:18)
        first = min(b[0] for b in judge.history if b[1] == "80.94.95.211")
        self.assertLess(first, datetime(2026, 9, 20, 1, 52, 18,
                                        tzinfo=timezone.utc).timestamp())

    def test_cloudflare_allowlist_matters(self):
        with open(os.path.join(DATA, "me.conf")) as f:
            text = "\n".join(ln for ln in f.read().splitlines()
                             if not ln.startswith("allow_file"))

        judge, _, _ = self.replay(text, "me.access.log")
        nets = [logban.ipaddress.ip_network(n) for n in CLOUDFLARE]
        edges = {b[1] for b in judge.history
                 if any(logban.ipaddress.ip_address(b[1]) in n for n in nets)}
        self.assertGreater(len(edges), 100)

    def test_generated_json_sample(self):
        # one request per address: nothing to ban, clusters included
        judge, lines, _ = self.replay(
            "costly = ^/(api|checkout|admin)/\nslow_seconds = 1.0\n"
            "watch errors = status:5..\nerrors.max = 5\n"
            "cluster_min_addresses = 10\ncluster_min_costly = 50\n",
            "clickHouse.access.log")
        self.assertEqual(judge.history, [])
        self.assertEqual(judge.skipped, 0)
        self.assertEqual(judge.lines, len(lines))


if __name__ == "__main__":
    unittest.main()

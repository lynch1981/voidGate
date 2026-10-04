#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run contrib/openresty/nginx.conf, as shipped, against a daemon in private
# namespaces: the honeypot (ban_now in access), 429s (ban in log), the
# status page (methods in content) and the health timer.
# Needs OpenResty, or nginx with lua-nginx-module, plus python3 for a stub
# backend; set NGINX to pick the binary.
set -euo pipefail

. "$(dirname "$0")/../bin/create_env.sh"

conf=$work/voidgate.conf
prefix=$work/nginx
example=$root/contrib/openresty/nginx.conf
backend=

nginx=${NGINX:-$(command -v openresty || command -v nginx || true)}
if [[ -z $nginx ]]; then
    echo "skip: no openresty or nginx in PATH (set NGINX)" >&2
    exit 0
fi

# refute <cmd...>: fail if cmd succeeds. Not "! cmd": set -e ignores a
# negated command, so "! grep ..." can never fail the script.
refute() {
    if "$@"; then
        echo "${0##*/}: unexpectedly true: $*" >&2
        return 1
    fi
}

cleanup() {
    local result=$?
    trap - EXIT
    if [[ $result != 0 && -e $prefix/error.log ]]; then
        cat "$prefix/error.log" >&2
    fi
    if [[ -e $prefix/nginx.pid ]]; then
        "$nginx" -p "$prefix" -c nginx.conf -s stop 2>/dev/null || true
    fi
    if [[ -n $backend ]]; then
        kill "$backend" 2>/dev/null || true
    fi
    if [[ -e $work/voidgate.pid ]]; then
        "$root/voidgate" -s stop -c "$conf" 2>/dev/null || true
    fi
    exit "$result"
}
trap cleanup EXIT

cp "$root/t/conf/idle.conf" "$conf"
printf 'log_file = %s\n' "$work/daemon.log" >> "$conf"
printf 'pid_file = %s\n' "$work/voidgate.pid" >> "$conf"
printf 'ctl_socket_group = nogroup\n' >> "$conf"
timeout --kill-after=2 10 "$root/voidgate" -d -c "$conf"

# The application: 200 for everything.
python3 - <<'PY' &
import http.server


class App(http.server.BaseHTTPRequestHandler):
    def reply(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = reply

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", 3000), App).serve_forever()
PY
backend=$!
for i in $(seq 50); do
    curl -s -o /dev/null http://127.0.0.1:3000/ && break
    sleep 0.1
done

# Render the example as shipped, changing only what a test host needs.
# Each substitution must match once, so a reshaped example fails here.
mkdir -p "$prefix/logs"
cp -r "$root/lua" "$work/lua"
chmod -R a+rX "$work"

render() {
    local from=$1 to=$2
    [[ $(grep -cF -- "$from" "$prefix/nginx.conf") == 1 ]] || {
        echo "example.sh: '$from' not found once in $example" >&2
        return 1
    }
    FROM=$from TO=$to perl -0pi -e 's/\Q$ENV{FROM}\E/$ENV{TO}/' \
        "$prefix/nginx.conf"
}

{
    for m in ndk_http_module ngx_http_lua_module; do
        if [[ -e /usr/lib/nginx/modules/$m.so ]]; then
            echo "load_module /usr/lib/nginx/modules/$m.so;"
        fi
    done
    echo "user nobody nogroup;"
    echo "pid $prefix/nginx.pid;"
    cat "$example"
} > "$prefix/nginx.conf"

render '"/usr/local/openresty/site/lualib/?.lua;;"' "\"$work/lua/?.lua;;\""
render 'listen 80;' 'listen 127.0.0.1:8081;'
render '# set_real_ip_from 10.0.0.0/8;' 'set_real_ip_from 127.0.0.1;'
render '# real_ip_header   X-Forwarded-For;' 'real_ip_header X-Forwarded-For;'

"$nginx" -p "$prefix" -e "$prefix/error.log" -c nginx.conf

# code <client-ip> <curl args...>: HTTP status of exactly one request (no
# --retry: curl would re-send a 429 and skew the rate-limit count).
code() {
    local ip=$1
    shift
    curl -sS -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $ip" "$@"
}

listed() {
    "$root/voidgatectl" drops | grep -q "^$1/32 reason=4 "
}

wait_listed() {
    local i
    for i in $(seq 50); do
        listed "$1" && return 0
        sleep 0.1
    done
    echo "example.sh: $1 not banned" >&2
    return 1
}

url=http://127.0.0.1:8081

for i in $(seq 50); do
    curl -s -o /dev/null "$url/voidgate/status" && break
    sleep 0.1
done

# Health timer and app up: an ordinary request passes.
[[ $(code 198.18.1.9 "$url/") == 200 ]]

# Honeypot: ban_now in access, so the drop is listed when the 403 returns.
[[ $(code 198.18.1.1 "$url/wp-login.php") == 403 ]]
listed 198.18.1.1

# A protected address is refused, logged, and still gets the 403.
[[ $(code 127.0.0.1 "$url/.env") == 403 ]]
grep -q 'voidgate ban_now 127.0.0.1: error: refused' "$prefix/error.log"

# Rate limit: a burst past 10 r/s + 20 gets 429s, then a ban.
seen429=0
for i in $(seq 60); do
    [[ $(code 198.18.1.3 "$url/") == 429 ]] && seen429=1
done
[[ $seen429 == 1 ]]
wait_listed 198.18.1.3

# Status page (methods in content), local only.
status=$(curl -sS "$url/voidgate/status")
[[ $status == state=active* ]]
grep -q '^198.18.1.1/32 reason=4 ' <<< "$status"
[[ $(code 198.18.1.9 "$url/voidgate/status") == 403 ]]

refute grep -q 'failed to run\|\[alert\]\|\[crit\]' "$prefix/error.log"

# Daemon gone: the honeypot still answers 403 and logs which ban failed,
# once. (nginx's own "[crit] connect() ... failed" line comes from its core
# connect code and is not ours to assert.)
"$root/voidgate" -s stop -c "$conf"
[[ $(code 198.18.1.4 "$url/wp-login.php") == 403 ]]
[[ $(grep -c 'voidgate ban_now 198.18.1.4: ' "$prefix/error.log") == 1 ]]

echo "openresty example tests passed"

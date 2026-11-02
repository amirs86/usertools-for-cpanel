# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
"""Tests for engine/site_doctor.py.

Run on Linux:  python -m pytest tests/test_site_doctor.py -q
"""
import http.server
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time

import pytest

ENGINE_DIR = os.path.join(os.path.dirname(__file__), "..", "engine")
ENGINE = os.path.join(ENGINE_DIR, "site_doctor.py")

sys.path.insert(0, os.path.abspath(ENGINE_DIR))
import site_doctor as sd
import perm_engine as pe


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def run_site(*argv, home=None, policy=None):
    """Run the engine CLI; return (returncode, summary_or_None, stderr)."""
    cmd = [sys.executable, ENGINE] + list(argv)
    if home is not None:
        cmd += ["--home", str(home)]
    if policy is not None:
        cmd += ["--policy", str(policy)]
    env = dict(os.environ)
    env["USERTOOLS_TESTING"] = "1"
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                          env=env)
    summary = None
    if proc.stdout.strip():
        try:
            summary = json.loads(proc.stdout)
        except json.JSONDecodeError:
            summary = None
    return proc.returncode, summary, proc.stderr


def make_home(tmp_path):
    """Fake home tree: returns the home Path."""
    home = tmp_path / "home"
    (home / "public_html").mkdir(parents=True)
    (home / "public_html" / "index.html").write_text("hi")
    return home


def lockless(*argv, home):
    """Run engine with an isolated lock dir (never touches ~/.cpanel)."""
    lockdir = os.path.join(str(home), "locks")
    return run_site(argv[0], "--lock-dir", lockdir, *argv[1:], home=home)


class ProbeApp(http.server.BaseHTTPRequestHandler):
    """Tiny virtual-host probe target: routes + Host header log."""
    routes = {}
    seen_hosts = []

    def _serve(self, head_only):
        ProbeApp.seen_hosts.append(self.headers.get("Host"))
        route = ProbeApp.routes.get(self.path, (404, {}, b"nope"))
        status, headers, body = route
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_HEAD(self):
        self._serve(True)

    def do_GET(self):
        self._serve(False)

    def log_message(self, *args):  # quiet
        pass


@pytest.fixture()
def web():
    """Local HTTP server on 127.0.0.1; yields (port, ProbeApp)."""
    ProbeApp.routes = {}
    ProbeApp.seen_hosts = []
    server = http.server.HTTPServer(("127.0.0.1", 0), ProbeApp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, ProbeApp
    finally:
        server.shutdown()
        thread.join(timeout=10)


def target_for(domain, docroot, port, php="ea-php82", fpm="1"):
    return "%s|%s|127.0.0.1|%d|%s|%s" % (
        domain, docroot, port, php, fpm)


def _file_server(docroot):
    """Tiny static file server rooted at docroot (logging off)."""
    import functools

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    handler = functools.partial(QuietHandler, directory=str(docroot))
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def etarget_for(domain, docroot, port):
    return "%s|%s|127.0.0.1|%d" % (domain, docroot, port)


# ---------------------------------------------------------------------------
# doctor-scan: homepage, docroot, .htaccess, logs
# ---------------------------------------------------------------------------

def test_doctor_homepage_ok(tmp_path, web):
    port, app = web
    app.routes["/"] = (200, {}, b"hello")
    home = make_home(tmp_path)
    tgt = target_for("example.test", str(home / "public_html"), port)
    rc, summary, _ = lockless("doctor-scan", "--target", tgt, home=home)
    assert rc == 0
    assert summary["command"] == "doctor-scan"
    assert len(summary["domains"]) == 1
    rec = summary["domains"][0]
    assert rec.get("deferred", False) is False
    assert rec["http"]["status"] == 200
    assert app.seen_hosts and app.seen_hosts[0] == "example.test"
    assert rec["docroot"]["usable"] is True
    assert rec["docroot"]["index"] == "index.html"
    assert rec["php"] == {"version": "ea-php82", "fpm": True}


def test_doctor_redirect_and_errors(tmp_path, web):
    port, app = web
    app.routes["/"] = (301, {"Location": "https://example.test/home"}, b"")
    home = make_home(tmp_path)
    tgt = target_for("example.test", str(home / "public_html"), port)
    rc, summary, _ = lockless("doctor-scan", "--target", tgt, home=home)
    assert rc == 0
    rec = summary["domains"][0]
    assert rec["http"]["status"] == 301
    assert rec["http"]["location"] == "https://example.test/home"
    assert rec["http"]["scheme"] == "http"


def _tls_http_server(tmp_path, body=b"served-target", status=200):
    """HTTPS server on 127.0.0.1 answering one fixed body (logging off)."""
    import ssl as _ssl
    key, crt, _der = _make_self_signed(tmp_path)
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                raw, _addr = srv.accept()
            except socket.timeout:
                continue
            try:
                with ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(5)
                    data = b""
                    try:
                        while b"\r\n\r\n" not in data:
                            chunk = tls.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                    except OSError:
                        pass
                    is_head = data.startswith(b"HEAD")
                    tls.sendall(
                        ("HTTP/1.1 %d Test\r\nContent-Length: %d\r\n"
                         "Connection: close\r\n\r\n"
                         % (status, len(body))).encode()
                        + (b"" if is_head else body))
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return srv, stop, thread, port


def _tls_path_server(tmp_path, routes, seen):
    """HTTPS server answering per-path (status, body); records paths + Host."""
    import ssl as _ssl
    key, crt, _der = _make_self_signed(tmp_path)
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                raw, _addr = srv.accept()
            except socket.timeout:
                continue
            try:
                with ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(5)
                    data = b""
                    try:
                        while b"\r\n\r\n" not in data:
                            chunk = tls.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                    except OSError:
                        pass
                    try:
                        head = data.split(b"\r\n", 1)[0].decode("iso-8859-1")
                        req_path = head.split(" ")[1] if " " in head else "/"
                    except (IndexError, ValueError):
                        req_path = "/"
                    seen.append(req_path)
                    host = ""
                    for line in data.split(b"\r\n"):
                        if line.lower().startswith(b"host:"):
                            host = line.split(b":", 1)[1].decode(
                                "iso-8859-1").strip()
                            break
                    seen.append("HOST:" + host)
                    status, body = routes.get(req_path, (404, b"nope"))
                    is_head = data.startswith(b"HEAD")
                    tls.sendall(
                        ("HTTP/1.1 %d Test\r\nContent-Length: %d\r\n"
                         "Connection: close\r\n\r\n"
                         % (status, len(body))).encode()
                        + (b"" if is_head else body))
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return srv, stop, thread, port


def test_www_variant_followed_when_listed(tmp_path, web):
    port, app = web
    seen = []
    srv, stop, thread, tlsport = _tls_path_server(
        tmp_path, {"/backup.sql": (200, b"dump\n")}, seen)
    try:
        app.routes["/backup.sql"] = (
            301, {"Location": "https://www.example.test:%d/" % tlsport},
            b"")
        out = sd.http_probe("127.0.0.1", port, "example.test",
                            "/backup.sql", 5, https_port=tlsport,
                            alt_hosts=["example.test", "www.example.test"])
    finally:
        stop.set()
        thread.join(timeout=10)
        srv.close()
    assert out["status"] == 200, out
    assert out["scheme"] == "https"
    assert out["exposed"] is True
    assert "/backup.sql" in seen, seen
    assert "HOST:www.example.test" in seen, seen
    state, _reason = sd.finding_state(out)
    assert state == "exposed"


def test_www_variant_not_listed_stays_not_checked(tmp_path, web):
    port, app = web
    seen = []
    srv, stop, thread, tlsport = _tls_path_server(
        tmp_path, {"/backup.sql": (200, b"dump\n")}, seen)
    try:
        app.routes["/backup.sql"] = (
            301, {"Location": "https://www.example.test:%d/" % tlsport},
            b"")
        out = sd.http_probe("127.0.0.1", port, "example.test",
                            "/backup.sql", 5, https_port=tlsport,
                            alt_hosts=["example.test"])
    finally:
        stop.set()
        thread.join(timeout=10)
        srv.close()
    assert out["status"] == 301, out
    assert out["scheme"] == "http"
    assert out["exposed"] is False
    assert seen == [], seen
    state, reason = sd.finding_state(out)
    assert state == "not_checked"
    assert "redirects to" in reason


def test_redirect_to_slash_probes_original_path(tmp_path, web):
    port, app = web
    seen = []
    srv, stop, thread, tlsport = _tls_path_server(
        tmp_path, {"/": (200, b"home"), "/backup.sql": (404, b"nope")},
        seen)
    try:
        app.routes["/backup.sql"] = (
            301, {"Location": "https://example.test:%d/" % tlsport},
            b"")
        out = sd.http_probe("127.0.0.1", port, "example.test",
                            "/backup.sql", 5, https_port=tlsport,
                            alt_hosts=["example.test"])
    finally:
        stop.set()
        thread.join(timeout=10)
        srv.close()
    assert out["status"] == 404, out
    assert out["scheme"] == "https"
    assert out["exposed"] is False
    assert "/backup.sql" in seen, seen
    assert "/" not in [p for p in seen if not p.startswith("HOST:")], seen
    state, _reason = sd.finding_state(out)
    assert state == "not_exposed"


def test_hop_failure_is_not_checked(tmp_path, web):
    port, app = web
    app.routes["/"] = (
        301, {"Location": "https://example.test:1/gone"}, b"")
    out = sd.http_probe("127.0.0.1", port, "example.test", "/", 5,
                        https_port=1)
    assert out["status"] == 301
    assert "https follow failed" in (out["error"] or "")
    state, reason = sd.finding_state(out)
    assert state == "not_checked"
    assert "redirects to" in reason


def test_finding_state_table():
    assert sd.finding_state({"exposed": True, "status": 200})[0] == "exposed"
    for good in (401, 403, 404, 410):
        s, r = sd.finding_state({"exposed": False, "status": good})
        assert s == "not_exposed", good
        assert r is None
    s, r = sd.finding_state(
        {"exposed": False, "status": 301, "location": "https://x/"})
    assert s == "not_checked" and "redirects to" in r
    s, r = sd.finding_state({"exposed": False, "status": 500})
    assert s == "not_checked" and "server error 500" in r
    s, r = sd.finding_state(
        {"exposed": False, "status": 0, "error": "boom"})
    assert s == "not_checked" and "boom" in r


def test_https_hop_followed_same_host(tmp_path, web):
    port, app = web
    srv, stop, thread, tlsport = _tls_http_server(tmp_path)
    try:
        app.routes["/start"] = (
            301, {"Location": "https://example.test:%d/target" % tlsport},
            b"")
        out = sd.http_probe("127.0.0.1", port, "example.test", "/start", 5,
                            https_port=tlsport)
    finally:
        stop.set()
        thread.join(timeout=10)
        srv.close()
    assert out["status"] == 200, out
    assert out["scheme"] == "https"
    assert out["exposed"] is True
    assert out["length"] == len(b"served-target")


def test_https_hop_other_host_ignored(tmp_path, web):
    port, app = web
    app.routes["/"] = (301, {"Location": "https://other.test/"}, b"")
    out = sd.http_probe("127.0.0.1", port, "example.test", "/", 5)
    assert out["status"] == 301
    assert out["scheme"] == "http"


def test_https_hop_plain_http_kept(tmp_path, web):
    port, app = web
    app.routes["/"] = (301, {"Location": "http://example.test/other"}, b"")
    out = sd.http_probe("127.0.0.1", port, "example.test", "/", 5)
    assert out["status"] == 301
    assert out["scheme"] == "http"


def test_https_hop_failure_keeps_redirect(tmp_path, web):
    port, app = web
    app.routes["/"] = (
        301, {"Location": "https://example.test:1/gone"}, b"")
    out = sd.http_probe("127.0.0.1", port, "example.test", "/", 5,
                        https_port=1)
    assert out["status"] == 301
    assert out["scheme"] == "http"
    assert out["location"] == "https://example.test:1/gone"
    assert "https follow failed" in (out["error"] or "")


def test_doctor_follows_same_host_https(tmp_path, web):
    port, app = web
    srv, stop, thread, tlsport = _tls_http_server(
        tmp_path, body=b"secure home")
    try:
        app.routes["/"] = (
            301, {"Location": "https://example.test:%d/" % tlsport}, b"")
        home = make_home(tmp_path)
        summary = sd.new_clean_summary("doctor-scan", str(home), True)
        checker = sd.Checker(
            str(home), os.getuid(), summary, lambda d, s: None,
            time.monotonic() + 30, 0, os.stat(str(home)).st_dev, 5,
            tlsport)
        rec = checker.check_one({
            "domain": "example.test",
            "docroot": str(home / "public_html"),
            "ip": "127.0.0.1", "port": port,
            "php": "ea-php82", "fpm": True})
    finally:
        stop.set()
        thread.join(timeout=10)
        srv.close()
    assert rec["http"]["status"] == 200
    assert rec["http"]["scheme"] == "https"


def test_doctor_htaccess_flags(tmp_path, web):
    port, _app = web
    home = make_home(tmp_path)
    (home / "public_html" / ".htaccess").write_text(
        "RewriteEngine Off\n"
        "php_value upload_max_filesize 64M\n"
        "php_flag display_errors Off\n"
        "RewriteRule ^old$ /new [R=301,L]\n")
    tgt = target_for("example.test", str(home / "public_html"), port)
    rc, summary, _ = lockless("doctor-scan", "--target", tgt, home=home)
    assert rc == 0
    ht = summary["domains"][0]["htaccess"]
    assert ht["present"] is True
    assert ht["php_value_lines"] == [2, 3]
    assert ht["missing_rewrite_engine"] is True
    assert ht["marker"] is False


def test_htaccess_guarded_blocks_ignored(tmp_path, web):
    port, _app = web
    home = make_home(tmp_path)
    (home / "public_html" / ".htaccess").write_text(
        "<IfModule php8_module>\n"
        "php_value upload_max_filesize 64M\n"
        "php_flag display_errors Off\n"
        "</IfModule>\n"
        "<IfModule !mod_php.c>\n"
        "php_value max_execution_time 60\n"
        "</IfModule>\n"
        "php_value memory_limit 256M\n")
    tgt = target_for("example.test", str(home / "public_html"), port)
    rc, summary, _ = lockless("doctor-scan", "--target", tgt, home=home)
    assert rc == 0
    ht = summary["domains"][0]["htaccess"]
    # cPanel's own guarded lines are skipped; the negated guard and the
    # bare line still count
    assert ht["php_value_lines"] == [6, 8]


def test_doctor_error_log_tails(tmp_path, web):
    port, _app = web
    home = make_home(tmp_path)
    (home / "public_html" / "error_log").write_text(
        "".join("line %d\n" % i for i in range(30)))
    (home / "logs").mkdir()
    (home / "logs" / "example_test.php.error.log").write_text("php broke\n")
    tgt = target_for("example.test", str(home / "public_html"), port)
    rc, summary, _ = lockless("doctor-scan", "--target", tgt, home=home)
    assert rc == 0
    logs = summary["domains"][0]["logs"]
    assert logs["docroot_log"][-1] == "line 29"
    assert len(logs["docroot_log"]) == 20
    assert logs["php_log"] == ["php broke"]


def test_cert_days_left_math():
    # notAfter format from getpeercert(), e.g. "Nov  2 06:00:00 2027 GMT"
    now = 1795000000.0
    assert sd.cert_days_left("Nov  2 06:00:00 2027 GMT", now) == (
        int((sd.ssl.cert_time_to_seconds("Nov  2 06:00:00 2027 GMT") - now) // 86400))
    assert sd.cert_days_left("not a date", now) is None


def _make_self_signed(tmp_path, days=30):
    key = str(tmp_path / "t.key")
    crt = str(tmp_path / "t.crt")
    der = str(tmp_path / "t.der")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", str(days),
         "-subj", "/CN=example.test"], check=True, capture_output=True)
    subprocess.run(
        ["openssl", "x509", "-in", crt, "-outform", "DER", "-out", der],
        check=True, capture_output=True)
    with open(der, "rb") as fh:
        return key, crt, fh.read()


def test_der_notafter_epoch(tmp_path):
    _key, _crt, der = _make_self_signed(tmp_path, days=30)
    exp = sd.der_cert_notafter_epoch(der)
    assert exp is not None
    import calendar
    now = calendar.timegm(time.gmtime())
    assert 29 * 86400 < exp - now <= 30 * 86400
    assert sd.der_cert_notafter_epoch(b"junk") is None
    assert sd.der_cert_notafter_epoch(b"\x30\x03\x01\x01\xff") is None


def test_tls_expiry_against_local_server(tmp_path):
    import ssl as _ssl
    key, crt, _der = _make_self_signed(tmp_path, days=30)
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                raw, _addr = srv.accept()
            except socket.timeout:
                continue
            try:
                with ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(1)
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        out = sd.tls_expiry("127.0.0.1", "example.test", 5, port)
    finally:
        stop.set()
        thread.join(timeout=10)
        srv.close()
    assert out["ok"] is True, out
    assert 0 <= out["days_left"] <= 30


def test_tls_failure_recorded_not_fatal(tmp_path):
    home = make_home(tmp_path)
    # Closed port: the handshake fails, the domain still gets a record.
    tgt = target_for("example.test", str(home / "public_html"), 1)
    rc, summary, _ = lockless("doctor-scan", "--target", tgt, home=home)
    assert rc == 0
    rec = summary["domains"][0]
    assert rec["ssl"]["ok"] is False
    assert rec["ssl"]["error"]


def test_doctor_deferral_and_validation(tmp_path):
    home = make_home(tmp_path)
    good = target_for("a.test", str(home / "public_html"), 8080)
    # max domains: 11 targets -> the 11th is deferred
    many = [target_for("d%d.test" % i, str(home / "public_html"), 8080)
            for i in range(11)]
    rc, summary, _ = lockless("doctor-scan", *sum(
        [["--target", t] for t in many], []), home=home)
    assert rc == 0
    assert len(summary["domains"]) == 11
    assert summary["domains"][-1]["domain"] == "d10.test"
    assert summary["domains"][-1]["deferred"] is True
    # shape validation happens before any network (usage error, code 2)
    for bad in ("nodomain", "a.test|relative|127.0.0.1|80|ea-php82|1",
                "a.test|/x|999.0.0.1|80|ea-php82|1",
                "a.test|/x|127.0.0.1|99999|ea-php82|1",
                "%s|/x|127.0.0.1|80|ea-php82|2" % "a.test"):
        rc, summary, _ = lockless("doctor-scan", "--target", bad, home=home)
        assert rc == 2, bad
    # duplicate domains refused
    rc, summary, _ = lockless("doctor-scan", "--target", good,
                              "--target", good, home=home)
    assert rc == 2
    # docroot outside the home is a per-domain error, not a crash
    rc, summary, _ = lockless(
        "doctor-scan", "--target",
        target_for("evil.test", str(tmp_path / "elsewhere"), 8080), home=home)
    assert rc == 0
    rec = summary["domains"][0]
    assert rec["docroot"]["usable"] is False


def test_blockable_names():
    assert sd.is_blockable_name("public_html/backup.sql")
    assert sd.is_blockable_name("/backup.sql")
    assert sd.is_blockable_name("a b.sql")
    for bad in ('we"ird.sql', "quo'te.sql", "back\\slash.sql",
                "back`tick.sql", "new\nline.sql", "tab\there.sql",
                "caf\xc3\xa9.sql", "del\x7f.sql", "ctl\x01.sql",
                "a%{b.sql", "a%{HTTP_HOST}.sql", "%", "%{",
                "pay$1.sql", "$1", "price$.sql",
                "", None, 123):
        assert not sd.is_blockable_name(bad), repr(bad)


def test_exposed_scan_marks_unsafe_names(tmp_path):
    home = make_home(tmp_path)
    seed_exposed(home)
    (home / "public_html" / 'we"ird.sql').write_text("dump\n")
    srv, thread = _file_server(home / "public_html")
    try:
        tgt = etarget_for("example.test", str(home / "public_html"),
                          srv.server_address[1])
        rc, summary, _ = lockless("exposed-scan", "--target", tgt, home=home)
    finally:
        srv.shutdown()
        thread.join(timeout=10)
    assert rc == 0
    by_rel = {f["relpath"]: f for f in summary["findings"]}
    assert by_rel["public_html/backup.sql"]["blockable"] is True
    assert by_rel['public_html/we"ird.sql']["blockable"] is False
    assert by_rel['public_html/we"ird.sql']["exposed"] is True


def test_get_never_reads_more_than_cap(tmp_path):
    # The server advertises 5 MB but drips one byte per half second: a
    # probe that read the body would take forever; header-only returns
    # in milliseconds with the right status and length.
    body_len = 5000000
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                raw, _addr = srv.accept()
            except socket.timeout:
                continue
            try:
                raw.settimeout(5)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                raw.sendall(
                    ("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                     "Connection: close\r\n\r\n" % body_len).encode())
                for _ in range(600):
                    if stop.is_set():
                        break
                    try:
                        raw.sendall(b"x")
                    except OSError:
                        break
                    time.sleep(0.5)
            except OSError:
                pass
            finally:
                try:
                    raw.close()
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        t0 = time.monotonic()
        out = sd.http_probe("127.0.0.1", port, "example.test", "/big",
                            5)
        dt = time.monotonic() - t0
    finally:
        stop.set()
        thread.join(timeout=10)
        srv.close()
    assert out["status"] == 200, out
    assert out["length"] == body_len
    assert out["exposed"] is True
    assert dt < 4.0, dt


def test_confidence_confirmed_and_likely(tmp_path, web):
    port, app = web
    home = make_home(tmp_path)
    seed_exposed(home)
    # backup.sql served byte-identical (5 on disk, 5 served): confirmed.
    # info.php (17 on disk) served as 5 bytes: downloadable but likely.
    app.routes["/backup.sql"] = (200, {}, b"dump\n")
    app.routes["/info.php"] = (200, {}, b"short")
    app.routes["/.git/HEAD"] = (200, {}, b"ref: refs/heads/main\n")
    tgt = etarget_for("example.test", str(home / "public_html"), port)
    rc, summary, _ = lockless("exposed-scan", "--target", tgt, home=home)
    assert rc == 0
    by_rel = {f["relpath"]: f for f in summary["findings"]}
    assert by_rel["public_html/backup.sql"]["confidence"] == "confirmed"
    assert by_rel["public_html/backup.sql"]["scheme"] == "http"
    assert by_rel["public_html/info.php"]["confidence"] == "likely"
    assert by_rel["public_html/.git"]["confidence"] == "confirmed"


def test_classify_exposed_names():
    cases = {
        ".git": "git_dir",
        "backup.sql": "sql_dump",
        "dump.sql.gz": "sql_dump",
        "old.zip": "archive",
        "site.tar.gz": "archive",
        "site.tar": "archive",
        "notes.bak": "backup_bak",
        "notes.txt~": "backup_tilde",
        "wp-config.php.bak": "wp_config_copy",
        "wp-config.php~": "backup_tilde",
        ".env": "env_copy",
        ".env.bak": "env_copy",
        "phpinfo.php": "phpinfo",
        "info.php": "phpinfo",
        "adminer.php": "adminer",
        "adminer-4.8.php": "adminer",
        "debug.log": "log_file",
        "index.php": None,
        "wp-config.php": None,
        "style.css": None,
        "photo.sql.jpg": None,
    }
    for name, want in cases.items():
        got = sd.classify_exposed(name, name == ".git")
        assert got == want, name
    assert sd.classify_exposed(".git", True) == "git_dir"
    assert sd.classify_exposed("anything", True) is None
    assert sd.classify_exposed(".git", False) is None


def seed_exposed(home):
    doc = home / "public_html"
    (doc / ".git").mkdir(parents=True)
    (doc / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (doc / "backup.sql").write_text("dump\n")
    (doc / "wp-config.php.bak").write_text("copy\n")
    (doc / "wp-config.php").write_text("real\n")
    (doc / ".env").write_text("SECRET=x\n")
    (doc / "info.php").write_text("<?php phpinfo();\n")
    (doc / "notes.txt~").write_text("tilde\n")
    (doc / "debug.log").write_text("log\n")
    (doc / "index.php").write_text("home\n")
    sub = doc / "sub"
    sub.mkdir()
    (sub / "old.zip").write_text("zip\n")
    deep = doc / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    (deep / "deep.sql").write_text("depth four\n")
    deeper = deep / "e"
    deeper.mkdir()
    (deeper / "deeper.sql").write_text("too deep\n")
    (doc / "adminer-4.8.php").write_text("adminer\n")
    return doc


def test_exposed_scan_and_probe(tmp_path):
    home = make_home(tmp_path)
    seed_exposed(home)
    srv, thread = _file_server(home / "public_html")
    try:
        tgt = etarget_for("example.test", str(home / "public_html"),
                          srv.server_address[1])
        rc, summary, _ = lockless("exposed-scan", "--target", tgt, home=home)
    finally:
        srv.shutdown()
        thread.join(timeout=10)
    assert rc == 0
    by_rel = {f["relpath"]: f for f in summary["findings"]}
    assert by_rel["public_html/.git"]["kind"] == "git_dir"
    assert by_rel["public_html/.git"]["exposed"] is True
    assert by_rel["public_html/.git"]["urlpath"] == "/.git/HEAD"
    assert by_rel["public_html/backup.sql"]["http_status"] == 200
    assert by_rel["public_html/backup.sql"]["exposed"] is True
    assert by_rel["public_html/backup.sql"]["urlpath"] == "/backup.sql"
    assert by_rel["public_html/backup.sql"]["confidence"] == "confirmed"
    assert by_rel["public_html/backup.sql"]["scheme"] == "http"
    assert by_rel["public_html/backup.sql"]["blockable"] is True
    assert by_rel["public_html/wp-config.php.bak"]["kind"] == "wp_config_copy"
    assert "public_html/wp-config.php" not in by_rel
    assert "public_html/.env" in by_rel
    assert "public_html/info.php" in by_rel
    assert "public_html/notes.txt~" in by_rel
    assert "public_html/debug.log" in by_rel
    assert "public_html/sub/old.zip" in by_rel
    assert "public_html/adminer-4.8.php" in by_rel
    assert "public_html/a/b/c/d/deep.sql" in by_rel  # depth 4 is still walked
    assert "public_html/a/b/c/d/e/deeper.sql" not in by_rel  # depth 5 is not
    assert "public_html/index.php" not in by_rel
    ids = [f["id"] for f in summary["findings"]]
    assert ids == ["f%d" % i for i in range(1, len(ids) + 1)]
    assert summary["counts"]["probed"] >= len(ids)


def test_exposed_move_restore_round_trip(tmp_path):
    home = make_home(tmp_path)
    seed_exposed(home)
    srv, thread = _file_server(home / "public_html")
    try:
        tgt = etarget_for("example.test", str(home / "public_html"),
                          srv.server_address[1])
        rc, summary, _ = lockless("exposed-scan", "--target", tgt, home=home)
        assert rc == 0
        # the engine summary carries no job id (the UAPI layer records that);
        # persist it the way the UAPI would so move/restore can resolve it
        jobs = home / ".cpanel" / "usertools" / "jobs"
        jobs.mkdir(parents=True)
        (jobs / "exposed-test.result.json").write_text(json.dumps(summary))
        finding = [f for f in summary["findings"]
                   if f["relpath"] == "public_html/backup.sql"][0]
        rc, summary, _ = lockless("exposed-move", "--job", "exposed-test",
                                  "--finding", finding["id"], home=home)
        assert rc == 0
        assert summary["counts"]["moved"] == 1
        assert summary["counts"]["changed"] == 1
        assert not os.path.lexists(str(home / "public_html" / "backup.sql"))
        qdir = home / ".usertools-quarantine"
        batches = [d for d in os.listdir(str(qdir))]
        assert len(batches) == 1
        # restore needs the finding id again: re-read from the same job file
        rc, summary, _ = lockless("exposed-restore", "--batch", batches[0],
                                  home=home)
        assert rc == 0
        assert summary["counts"]["restored"] == 1
        assert (home / "public_html" / "backup.sql").read_bytes() == b"dump\n"
        # full restore removes the batch
        assert os.listdir(str(qdir)) == []
        # unknown job / finding refused
        rc, summary, _ = lockless("exposed-move", "--job", "nope",
                                  "--finding", "f1", home=home)
        assert rc == 2
        rc, summary, _ = lockless("exposed-move", "--job", "exposed-test",
                                  "--finding", "zzz", home=home)
        assert rc == 2
    finally:
        srv.shutdown()
        thread.join(timeout=10)


def test_quarantine_partial_restore_keeps_conflicts(tmp_path):
    home = make_home(tmp_path)
    seed_exposed(home)
    srv, thread = _file_server(home / "public_html")
    try:
        tgt = etarget_for("example.test", str(home / "public_html"),
                          srv.server_address[1])
        rc, summary, _ = lockless("exposed-scan", "--target", tgt, home=home)
        assert rc == 0
        jobs = home / ".cpanel" / "usertools" / "jobs"
        jobs.mkdir(parents=True)
        (jobs / "exposed-test.result.json").write_text(json.dumps(summary))
        by_rel = {f["relpath"]: f for f in summary["findings"]}
        for rel in ("public_html/backup.sql", "public_html/info.php"):
            rc, summary, _ = lockless(
                "exposed-move", "--job", "exposed-test",
                "--finding", by_rel[rel]["id"], home=home)
            assert rc == 0
        (home / "public_html" / "info.php").write_bytes(b"recreated")
        # Each move creates its own batch, so map batch -> entry path.
        qroot = str(home / ".usertools-quarantine")
        batches = sorted(os.listdir(qroot))
        assert len(batches) == 2

        def batch_entry(b):
            with open(os.path.join(qroot, b, "manifest.json")) as fh:
                return json.load(fh)["entries"][0]["path"]

        by_entry = {batch_entry(b): b for b in batches}
        assert set(by_entry) == {
            "public_html/backup.sql", "public_html/info.php"}
        # backup.sql restores cleanly and its batch goes away
        rc, summary, _ = lockless(
            "exposed-restore", "--batch",
            by_entry["public_html/backup.sql"], home=home)
        assert rc == 0
        assert summary["counts"]["restored"] == 1
        assert summary["counts"]["restore_conflicts"] == 0
        assert (home / "public_html" / "backup.sql").read_bytes() == b"dump\n"
        # info.php conflicts: the recreated file wins, the copy stays
        rc, summary, _ = lockless(
            "exposed-restore", "--batch",
            by_entry["public_html/info.php"], home=home)
        assert rc == 0
        assert summary["counts"]["restored"] == 0
        assert summary["counts"]["restore_conflicts"] == 1
        assert (home / "public_html" / "info.php").read_bytes() == b"recreated"
        batch = by_entry["public_html/info.php"]
        with open(os.path.join(qroot, batch, "manifest.json")) as fh:
            manifest = json.load(fh)
        assert [e["path"] for e in manifest["entries"]] == ["public_html/info.php"]
    finally:
        srv.shutdown()
        thread.join(timeout=10)


def test_quarantine_moves_directory(tmp_path):
    home = make_home(tmp_path)
    seed_exposed(home)
    srv, thread = _file_server(home / "public_html")
    try:
        tgt = etarget_for("example.test", str(home / "public_html"),
                          srv.server_address[1])
        rc, summary, _ = lockless("exposed-scan", "--target", tgt, home=home)
        assert rc == 0
        jobs = home / ".cpanel" / "usertools" / "jobs"
        jobs.mkdir(parents=True)
        (jobs / "exposed-test.result.json").write_text(json.dumps(summary))
        finding = [f for f in summary["findings"]
                   if f["relpath"] == "public_html/.git"][0]
        rc, summary, _ = lockless("exposed-move", "--job", "exposed-test",
                                  "--finding", finding["id"], home=home)
        assert rc == 0
        assert summary["counts"]["moved"] == 1
        assert not os.path.lexists(str(home / "public_html" / ".git"))
        batch = os.listdir(str(home / ".usertools-quarantine"))[0]
        rc, summary, _ = lockless("exposed-restore", "--batch", batch,
                                  home=home)
        assert rc == 0
        assert (home / "public_html" / ".git" / "HEAD").read_bytes() == \
            b"ref: refs/heads/main\n"
    finally:
        srv.shutdown()
        thread.join(timeout=10)


def test_quarantine_conflict_keeps_copy(tmp_path):
    home = make_home(tmp_path)
    seed_exposed(home)
    srv, thread = _file_server(home / "public_html")
    try:
        tgt = etarget_for("example.test", str(home / "public_html"),
                          srv.server_address[1])
        rc, summary, _ = lockless("exposed-scan", "--target", tgt, home=home)
        assert rc == 0
        jobs = home / ".cpanel" / "usertools" / "jobs"
        jobs.mkdir(parents=True)
        (jobs / "exposed-test.result.json").write_text(json.dumps(summary))
        finding = [f for f in summary["findings"]
                   if f["relpath"] == "public_html/backup.sql"][0]
        lockless("exposed-move", "--job", "exposed-test",
                 "--finding", finding["id"], home=home)
        (home / "public_html" / "backup.sql").write_bytes(b"recreated")
        batch = os.listdir(str(home / ".usertools-quarantine"))[0]
        rc, summary, _ = lockless("exposed-restore", "--batch", batch, home=home)
        assert rc == 0
        assert summary["counts"]["restored"] == 0
        assert summary["counts"]["restore_conflicts"] == 1
        assert (home / "public_html" / "backup.sql").read_bytes() == b"recreated"
    finally:
        srv.shutdown()
        thread.join(timeout=10)

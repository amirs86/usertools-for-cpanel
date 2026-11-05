#!/usr/bin/python3
# Copyright 2026 Amir Sibaee (https://as86.pro)
# SPDX-License-Identifier: Apache-2.0
"""site_doctor.py - unprivileged site checks and exposed-file handling.

Runs ONLY as an unprivileged cPanel user. It checks the account's websites
(homepage status, document roots, .htaccess pitfalls, TLS certificates,
error logs, xmlrpc.php exposure on WordPress sites) and scans document roots for files that must never be public
(backups, dumps, copies of secrets). Anything it moves goes to a quarantine
folder inside the home with restore. It refuses to run as root.

Security properties (each covered by tests/test_site_doctor.py):

  * Never follows symlinks. Directories are opened with O_NOFOLLOW and every
    stat uses dir_fd with follow_symlinks=False. Symlinks are recorded and
    left alone; nothing is ever probed, moved or restored through one.
  * Stays on one filesystem and inside the caller's home: every docroot is
    canonicalised with realpath and must lie inside the home; entries whose
    st_dev differs are skipped, so a quarantine move (rename) can never
    cross filesystems and a restore can never escape the home.
  * Never takes paths from the caller for anything that writes or deletes.
    Scans enumerate the server-side document roots passed on the command
    line; quarantine and restore resolve finding ids against the scan job's
    own result file, never against request data. Probe URLs are built from
    the server-side domain plus the walked relative path only.
  * Probing is status and size only: HEAD first, then a capped GET.
    Bodies are read up to a cap and discarded, never stored or returned.
    The homepage check follows up to ten redirects to the same literal IP,
    the listed domain or its www/bare counterpart. Chain URLs always use
    the scheme's standard port while connections go to the record's backend
    port, and it reports a loop, too many redirects, an off-site hop or the
    final URL. Exposed-file and xmlrpc.php probes keep their single same-host
    HTTPS hop. Served bytes count as confirmed only when
    their length matches the file on disk, otherwise likely (soft 404s
    answer 200 for anything). Names that cannot appear in a .htaccess rule
    are marked unblockable: those are moved, never blocked.
  * One live job per user: the same lock file as the other engines, so a
    scan never overlaps another job.

Usage:
  site_doctor.py doctor-scan --target D|R|I|P|V|F ... [options]
  site_doctor.py exposed-scan --target D|R|I|P ... [options]
  site_doctor.py exposed-move --job ID --finding FID [options]
  site_doctor.py exposed-restore --batch ID [options]

  Each --target names one website; fields are domain, absolute docroot,
  probe IP, probe port, PHP version and PHP-FPM flag (doctor only), joined
  by "|". At most 10 websites inside a 30 s budget; the rest are deferred.
  doctor-scan reads the homepage, the docroot, .htaccess pitfalls, the TLS
  certificate and both error logs and reports one fact record per domain.
  exposed-scan walks every docroot (max depth 4) for files that must never
  be public and probes each one over HTTP: exposed only when the server
  actually serves it (status 200/206). exposed-move quarantines one finding
  (resolved against the scan job's own result, never from the request) to
  ~/.usertools-quarantine/<batch>/ (0700, manifest.json, restore available);
  exposed-restore puts a whole batch back when each original path is free
  (conflicts reported, never overwritten).

Exit codes: 0 ok, 2 usage/validation/refusal, 3 another job running,
4 resource limit (EMFILE/ENFILE: partial run, summary still printed),
5 timed out or interrupted by SIGTERM (partial run, summary still printed),
1 unexpected failure.
"""

import argparse
import errno
import http.client
import json
import os
import re
import signal
import socket
import ssl
import stat
import sys
import time
import urllib.parse

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX (engine targets Linux)
    fcntl = None  # type: ignore

import perm_engine as pe
import space_cleaner as sclean

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_DOMAINS = 10
BUDGET_SECONDS = 30
REQUEST_TIMEOUT = 5
READ_CAP = 65536
HTACCESS_MAX_BYTES = 65536
LOG_TAIL_BYTES = 65536
LOG_TAIL_LINES = 20

INDEX_NAMES = (
    "index.html", "index.htm", "index.php", "default.html",
    "default.htm", "home.html",
)

# Exposed-file patterns: (kind, test). Directories only match ".git".
EXPOSED_SQL_RE = re.compile(r"\.sql(\.gz)?$", re.IGNORECASE)
EXPOSED_ARCHIVE_RE = re.compile(r"\.(zip|tar|tar\.gz)$", re.IGNORECASE)

QUARANTINE_DIRNAME = ".usertools-quarantine"


class _WalkDone(Exception):
    """Internal unwind for timeout/interrupt (partial summary still valid)."""


def parse_target(text, want_php):
    # type: (str, bool) -> dict
    """Clean one --target value or raise UsageError.

    Shape: domain|docroot|ip|port[|php|fpm]. The domain is matched against
    [A-Za-z0-9.-]; the docroot must be absolute; the probe address must be
    a literal IP (never resolved here, never from DNS).
    """
    parts = text.split("|")
    if len(parts) != (6 if want_php else 4):
        raise pe.UsageError("bad --target (want %s fields): %r"
                            % ("D|R|I|P|V|F" if want_php else "D|R|I|P",
                               text))
    domain, docroot = parts[0], parts[1]
    if not re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$",
                    domain):
        raise pe.UsageError("bad domain in --target: %r" % domain)
    if not docroot.startswith("/"):
        raise pe.UsageError("docroot must be absolute: %r" % docroot)
    try:
        port = int(parts[3])
    except ValueError:
        raise pe.UsageError("bad port in --target: %r" % text)
    if port < 1 or port > 65535:
        raise pe.UsageError("bad port in --target: %r" % text)
    try:
        socket.inet_pton(socket.AF_INET, parts[2])
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, parts[2])
        except OSError:
            raise pe.UsageError("probe address must be a literal IP: %r"
                                % text)
    target = {"domain": domain, "docroot": docroot, "ip": parts[2],
              "port": port}
    if want_php:
        target["php"] = parts[4]
        if parts[5] not in ("0", "1"):
            raise pe.UsageError("bad fpm flag in --target: %r" % text)
        target["fpm"] = parts[5] == "1"
    return target


def parse_batch_id(text):
    # type: (str) -> str
    return sclean.parse_batch_id(text)


def quarantine_dir(home):
    # type: (str) -> str
    return os.path.join(home, QUARANTINE_DIRNAME)


def new_clean_summary(command, home, dry_run):
    # type: (str, str, bool) -> dict
    return {
        "command": command,
        "scope": home,
        "dry_run": dry_run,
        "counts": {
            "scanned": 0,
            "changed": 0,
            "would_change": 0,
            "not_owned": 0,
            "errors": 0,
            "skipped_symlink": 0,
            "skipped_protected": 0,
            "skipped_xdev": 0,
            "skipped_special": 0,
            "skipped_hardlink": 0,
            "probed": 0,
            "exposed": 0,
            "not_checked": 0,
            "moved": 0,
            "restored": 0,
            "restore_conflicts": 0,
        },
        "paths": {
            "moved": [],
            "restored": [],
            "not_owned": [],
            "skipped_symlink": [],
            "skipped_protected": [],
            "skipped_xdev": [],
            "skipped_special": [],
            "skipped_hardlink": [],
            "errors": [],
        },
        "omitted": {},
        "timed_out": False,
        "interrupted": False,
        "resource_limited": False,
        "quarantine_batch": None,
        "domains": [],
        "findings": [],
        "elapsed_seconds": 0.0,
    }


def _add_capped(summary, key, value):
    # type: (dict, str, object) -> None
    lst = summary["paths"][key]
    if len(lst) < sclean.PATH_CAP:
        lst.append(value)
    else:
        summary["omitted"][key] = summary["omitted"].get(key, 0) + 1


# ---------------------------------------------------------------------------
# HTTP probing (status only, capped bodies, one same-host HTTPS hop)
# ---------------------------------------------------------------------------

HTTPS_PORT = 443
HTTP_PORT = 80
MAX_REDIRECT_HOPS = 10
MAX_REDIRECT_SOURCES = 100
MAX_LOCATION_LENGTH = 2048
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _open_conn(ip, port, host, timeout, use_tls):
    # type: (str, int, str, float, bool) -> object
    """Plain or TLS connection to a literal IP (SNI = host for TLS).

    Certificate validation is off on purpose: the probe only needs the
    status line, and self-signed or AutoSSL-pending hosts must still
    answer. Timeouts bound the TCP connect and the TLS handshake alike.
    """
    if not use_tls:
        return http.client.HTTPConnection(ip, port, timeout=timeout)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except Exception:
        try:
            raw.close()
        except OSError:
            pass
        raise
    try:
        tls.settimeout(timeout)
    except OSError:
        pass
    # The socket is already connected and wrapped: http.client only
    # formats requests on top of it (connect() is skipped when sock
    # is set) and never sees the IP, so no Host header override is
    # needed to keep SNI and Host aligned on the domain.
    conn = http.client.HTTPSConnection(host, port, context=ctx,
                                       timeout=timeout)
    conn.sock = tls
    return conn


def _follow_target(location, host, https_port, alt_hosts):
    # type: (object, str, int, object) -> object
    """Decide whether a 3xx Location deserves the single same-host hop.

    Returns (use_host, None) or None. Follows only https URLs whose host
    is the probed domain itself, or its www/bare counterpart: cPanel
    always serves www.<listed domain> as an alias of each listed domain
    (and the bare form of a listed www. name), so the counterpart counts
    as listed without appearing in the server-side domain list
    (alt_hosts, any case). Takes only the scheme and host from the
    Location; the path re-probed is always the ORIGINAL one, so a
    redirect-everything-to-/ host cannot make an unserved file look
    served. The TLS port must match exactly. No DNS is ever consulted.
    """
    if not location or not isinstance(location, str):
        return None
    try:
        parts = urllib.parse.urlsplit(location)
    except ValueError:
        return None
    if parts.scheme.lower() != "https":
        return None
    if parts.username or parts.password:
        return None
    try:
        port = parts.port or 443
    except ValueError:
        return None
    if port != https_port:
        return None
    if not parts.hostname:
        return None
    target = parts.hostname.lower()
    if target == host.lower():
        return (host, None)
    base = host.lower()
    if base.startswith("www."):
        counterpart = base[4:]
    else:
        counterpart = "www." + base
    if target != counterpart:
        return None
    return (parts.hostname, None)


def _probe_scheme(ip, port, host, quoted, timeout, use_tls):
    # type: (str, int, str, str, float, bool) -> dict
    """One HEAD, then a capped GET fallback on 405/501/500.

    Returns {status, location, ms, length, exposed, error}. Bodies are
    never stored: with a known Content-Length nothing is read at all
    (the connection closes anyway); otherwise at most READ_CAP + 1
    bytes are read to learn the length. Length None means unknown.
    """
    t0 = time.monotonic()
    try:
        conn = _open_conn(ip, port, host, timeout, use_tls)
        try:
            conn.request("HEAD", quoted,
                         headers={"Host": host, "Connection": "close",
                                  "User-Agent": "UserTools-SiteDoctor"})
            resp = conn.getresponse()
            status = resp.status
            location = resp.getheader("Location")
            length = _content_length(resp)
            try:
                resp.read(READ_CAP + 1)
            except (OSError, http.client.HTTPException):
                pass
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError,
            ValueError) as exc:
        return {"status": 0, "location": None, "ms": None, "length": None,
                "exposed": False, "error": "request failed: %s" % exc}
    ms = round((time.monotonic() - t0) * 1000, 1)
    if status in (200, 206):
        return {"status": status, "location": None, "ms": ms,
                "length": length, "exposed": True, "error": None}
    if status not in (405, 501, 500):
        return {"status": status, "location": location, "ms": ms,
                "length": None, "exposed": False, "error": None}
    t0 = time.monotonic()
    try:
        conn = _open_conn(ip, port, host, timeout, use_tls)
        try:
            conn.request("GET", quoted,
                         headers={"Host": host, "Connection": "close",
                                  "User-Agent": "UserTools-SiteDoctor"})
            resp = conn.getresponse()
            status = resp.status
            location = resp.getheader("Location")
            length = _content_length(resp)
            if length is None:
                try:
                    length = len(resp.read(READ_CAP + 1))
                except (OSError, http.client.HTTPException):
                    length = None
            # Known length: read nothing. A huge dump is never
            # downloaded just to learn what the header already says.
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError,
            ValueError) as exc:
        return {"status": 0, "location": None, "ms": None, "length": None,
                "exposed": False, "error": "request failed: %s" % exc}
    ms = round((time.monotonic() - t0) * 1000, 1)
    return {"status": status, "location": location, "ms": ms,
            "length": length, "exposed": status in (200, 206),
            "error": None}


def http_probe(ip, port, host, path, timeout, https_port=None,
             alt_hosts=None):
    # type: (str, int, str, str, float, object, object) -> dict
    """Probe one URL path: HEAD, then a capped GET fallback.

    Returns {status, location, ms, length, exposed, error, scheme}.
    exposed is true only when the server actually serves the bytes
    (200/206). When plain HTTP answers 3xx to https://<same host> (or
    to its www/bare counterpart when that name belongs to the account,
    see alt_hosts), the probe is repeated once over TLS to the same
    literal IP (SNI and Host set to the followed name, never verified)
    and that verdict wins; scheme records which one answered. The hop
    always re-probes the ORIGINAL path, never the redirect target.
    Anything else is reported as-is: only the first redirect is ever
    shown, never followed further. Bodies are read up to READ_CAP and
    discarded, never stored. https_port overrides the TLS port (tests
    point it at a fixture; the default is 443).
    """
    if https_port is None:
        https_port = HTTPS_PORT
    if "\x00" in path or ".." in path.split("/"):
        return {"status": 0, "location": None, "ms": None, "length": None,
                "exposed": False,
                "error": "refusing to probe an unsafe path",
                "scheme": "http"}
    quoted = urllib.parse.quote(path, safe="/")
    first = _probe_scheme(ip, port, host, quoted, timeout, False)
    first["scheme"] = "http"
    if first["status"] in (301, 302, 303, 307, 308):
        hop = _follow_target(first.get("location"), host, https_port,
                             alt_hosts)
        if hop is not None:
            use_host, _hop_path = hop
            second = _probe_scheme(ip, https_port, use_host, quoted,
                                   timeout, True)
            second["scheme"] = "https"
            if second["status"] == 0 and second.get("error"):
                first["error"] = ("https follow failed: %s"
                                  % second["error"])
                return first
            return second
    return first


def _has_control(text):
    # type: (str) -> bool
    """True when a URL fragment contains control characters."""
    return any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text)


def _unsafe_request(path, query):
    # type: (str, str) -> bool
    """Reject paths this probe must never send (same rule as http_probe)."""
    return (_has_control(path) or _has_control(query)
            or "\x00" in path or ".." in path.split("/"))


def _quote_request(path, query):
    # type: (str, str) -> object
    """Quote one request target; None when the path is unsafe."""
    if _unsafe_request(path, query):
        return None
    quoted = urllib.parse.quote(path, safe="/%:@!$&'()*+,;=-._~")
    if query:
        quoted += "?" + urllib.parse.quote(
            query, safe="=&%:@!$'()*+,;/?-._~")
    return quoted


def _display_url(scheme, host, path, query):
    # type: (str, str, str, str) -> str
    """URL text for the page; always on the scheme's standard port."""
    tail = path
    if query:
        tail += "?" + query
    return "%s://%s%s" % (scheme, host, tail)


def _allowed_hosts(host):
    # type: (str) -> set
    """The listed domain plus its www/bare counterpart (any case)."""
    base = host.lower().rstrip(".")
    allowed = {base}
    if base.startswith("www."):
        allowed.add(base[4:])
    else:
        allowed.add("www." + base)
    return allowed


def _loop_key(scheme, host, path, query):
    # type: (str, str, str, str) -> tuple
    """The repeat test for a chain: scheme, host, path and query."""
    return (scheme.lower(), host.lower().rstrip("."), path or "/", query or "")


def _redirect_location(location, current_url, allowed, http_port, https_port):
    # type: (object, str, set, int, int) -> dict
    """Resolve one Location without DNS, cookies or a second address.

    The URL always carries the scheme's standard port implicitly. A
    Location may spell out that standard port, or the record's connection
    port for the same scheme when a backend leaks it; anything else stops.
    Returns {"target": ...}, {"leaves_to": host, "url": ...} for another
    host, or {"error": reason} when the address is not safe to probe.
    """
    if not isinstance(location, str) or len(location) > MAX_LOCATION_LENGTH \
            or _has_control(location):
        return {"error": "redirect address is not usable"}
    try:
        parts = urllib.parse.urlsplit(
            urllib.parse.urljoin(current_url, location))
    except ValueError:
        return {"error": "redirect address is not usable"}
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return {"error": "redirect is not http or https"}
    if parts.username or parts.password:
        return {"error": "redirect contains sign-in details"}
    try:
        host = parts.hostname
    except ValueError:
        return {"error": "redirect address has no usable host"}
    if not host:
        return {"error": "redirect address has no host"}
    host = host.lower().rstrip(".")
    try:
        explicit_port = parts.port
    except ValueError:
        return {"error": "redirect address has an invalid port"}
    path = parts.path or "/"
    query = parts.query or ""
    if _unsafe_request(path, query):
        return {"error": "redirect path cannot be probed safely"}
    url = _display_url(scheme, host, path, query)
    if host not in allowed:
        return {"leaves_to": host, "url": url}
    if scheme == "http":
        standard_port, record_port = HTTP_PORT, http_port
    else:
        standard_port, record_port = HTTPS_PORT, https_port
    if explicit_port is not None \
            and explicit_port not in (standard_port, record_port):
        return {"error": "redirect uses a non-standard port"}
    return {"target": {
        "scheme": scheme, "host": host,
        "path": path, "query": query, "url": url,
        "key": _loop_key(scheme, host, path, query),
    }}


def _chain_result(verdict, chain, urls, status, final_url, probe=None,
                  scheme="http", error=None, leaves_to=None, reason=None):
    # type: (str, list, list, int, str, object, str, object, object, object) -> dict
    """Build the homepage probe record shared with the engine summary."""
    last = chain[-1] if chain else {}
    body = probe if isinstance(probe, dict) else {}
    return {
        "status": status,
        "location": last.get("location"),
        "ms": last.get("ms"),
        "length": body.get("length"),
        "exposed": bool(body.get("exposed")),
        "error": error if error is not None else body.get("error"),
        "scheme": scheme,
        "verdict": verdict,
        "final_url": final_url,
        "leaves_to": leaves_to,
        "reason": reason,
        "chain": chain,
        "urls": urls,
        "redirects": max(0, len(chain) - 1),
    }


def http_chain(ip, port, host, path, timeout, https_port=None,
               max_hops=MAX_REDIRECT_HOPS):
    # type: (str, int, str, str, float, object, int) -> dict
    """Follow the homepage redirect chain on the same literal IP.

    HEAD first, then the capped GET fallback, exactly like http_probe.
    Every connection goes to `ip`; http uses the record's `port` and https
    uses `https_port`. The URLs in the chain use the standard ports and
    keep them implicit. Only the listed domain and its www/bare counterpart
    are allowed. A Location may omit its port, write the standard port, or
    leak the record's connection port for the same scheme; any other port
    stops the chain. A repeat of (scheme, host, path, query) stops as a
    loop. More than max_hops followed redirects stops as too_many. An
    off-site Location is reported as leaves_to and is never requested.
    Bodies are never stored.
    """
    if https_port is None:
        https_port = HTTPS_PORT
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    quoted = _quote_request(path, "")
    if quoted is None:
        return _chain_result("error", [], [], 0, "", scheme="http",
                             error="refusing to probe an unsafe path")
    allowed = _allowed_hosts(host)
    host = host.lower().rstrip(".")
    current = {
        "scheme": "http", "host": host,
        "path": path, "query": "",
        "url": _display_url("http", host, path, ""),
        "key": _loop_key("http", host, path, ""),
    }
    chain = []
    urls = []
    visited = set()
    redirects = 0
    while True:
        key = current["key"]
        visited.add(key)
        urls.append(current["url"])
        quoted = _quote_request(current["path"], current["query"])
        if quoted is None:
            return _chain_result(
                "error", chain, urls, 0, current["url"],
                scheme=current["scheme"],
                error="refusing to probe an unsafe path")
        conn_port = port if current["scheme"] == "http" else https_port
        probe = _probe_scheme(ip, conn_port, current["host"], quoted,
                              timeout, current["scheme"] == "https")
        status = probe.get("status") or 0
        if status == 0:
            # Keep the last response that did answer so the page can
            # still show the redirect that led to the failed request.
            last = chain[-1] if chain else {}
            return _chain_result(
                "stopped" if chain else "error", chain, urls,
                last.get("status") or 0, current["url"],
                probe=probe, scheme=last.get("scheme", current["scheme"]),
                error="follow failed: %s"
                % (probe.get("error") or "request failed"))
        chain.append({
            "url": current["url"],
            "scheme": current["scheme"],
            "status": status,
            "location": probe.get("location"),
            "ms": probe.get("ms"),
        })
        if status not in REDIRECT_STATUSES:
            return _chain_result(
                "ok", chain, urls, status, current["url"],
                probe=probe, scheme=current["scheme"])
        location = probe.get("location")
        if not location:
            return _chain_result(
                "ok", chain, urls, status, current["url"],
                probe=probe, scheme=current["scheme"])
        resolved = _redirect_location(location, current["url"], allowed,
                                      port, https_port)
        if "error" in resolved:
            return _chain_result(
                "stopped", chain, urls, status, current["url"],
                probe=probe, scheme=current["scheme"],
                error=probe.get("error"), reason=resolved["error"])
        if "leaves_to" in resolved:
            urls.append(resolved["url"])
            return _chain_result(
                "leaves", chain, urls, status, resolved["url"],
                probe=probe, scheme=current["scheme"],
                leaves_to=resolved["leaves_to"])
        target = resolved["target"]
        if redirects >= max_hops:
            urls.append(target["url"])
            return _chain_result(
                "too_many", chain, urls, status, target["url"],
                probe=probe, scheme=current["scheme"])
        if target["key"] in visited:
            urls.append(target["url"])
            return _chain_result(
                "loop", chain, urls, status, target["url"],
                probe=probe, scheme=current["scheme"])
        redirects += 1
        current = target


def _content_length(resp):
    # type: (object) -> object
    """Content-Length as an int, else None."""
    try:
        raw = resp.getheader("Content-Length")
    except (OSError, http.client.HTTPException):
        return None
    if raw is None:
        return None
    try:
        value = int(str(raw).strip())
    except ValueError:
        return None
    return value if value >= 0 else None
# ---------------------------------------------------------------------------
# TLS certificate check (handshake only, never verified)
# ---------------------------------------------------------------------------

def tls_expiry(ip, domain, timeout, port=443):
    # type: (str, str, float, int) -> dict
    """Days until the served certificate expires (SNI = domain).

    Returns {ok, days_left, error}. The handshake proves the front end
    answers for the domain; validation is off on purpose (self-signed
    and AutoSSL-pending hosts still report their dates). The port
    defaults to 443 (tests point it at a local TLS server).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        return {"ok": False, "days_left": None,
                "error": "connect failed: %s" % exc}
    try:
        try:
            tls = ctx.wrap_socket(raw, server_hostname=domain)
        except (OSError, ssl.SSLError, ValueError) as exc:
            try:
                raw.close()
            except OSError:
                pass
            return {"ok": False, "days_left": None,
                    "error": "handshake failed: %s" % exc}
        with tls:
            cert = tls.getpeercert()
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"ok": False, "days_left": None,
                "error": "handshake failed: %s" % exc}
    if isinstance(cert, dict) and cert.get("notAfter"):
        try:
            expires = ssl.cert_time_to_seconds(cert["notAfter"])
        except ValueError:
            expires = None
        if expires is not None:
            return {"ok": True,
                    "days_left": int((expires - time.time()) // 86400),
                    "error": None}
    # getpeercert() can come back empty on some TLS 1.3 stacks while the
    # binary form still carries the certificate: read the expiry date
    # straight from the DER validity sequence instead.
    expires = der_cert_notafter_epoch(der) if der else None
    if expires is None:
        return {"ok": False, "days_left": None,
                "error": "no certificate presented"}
    return {"ok": True,
            "days_left": int((expires - time.time()) // 86400),
            "error": None}


def _der_read_tlv(buf, off):
    # type: (bytes, int) -> tuple
    """Read one DER TLV at offset; returns (tag, value_off, value_len)."""
    if off + 2 > len(buf):
        raise ValueError("truncated")
    tag = buf[off]
    first = buf[off + 1]
    if first < 0x80:
        return tag, off + 2, first
    count = first & 0x7F
    if count == 0 or count > 4 or off + 2 + count > len(buf):
        raise ValueError("bad length")
    length = 0
    for i in range(count):
        length = (length << 8) | buf[off + 2 + i]
    return tag, off + 2 + count, length


def der_cert_notafter_epoch(der):
    # type: (bytes) -> object
    """UTC epoch of a DER certificate's notAfter, or None."""
    try:
        if not isinstance(der, (bytes, bytearray)) or len(der) < 10:
            return None
        # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, ... }
        tag, voff, _vlen = _der_read_tlv(der, 0)
        if tag != 0x30:
            return None
        # tbsCertificate SEQUENCE
        tag, voff, vlen = _der_read_tlv(der, voff)
        if tag != 0x30:
            return None
        end = voff + vlen
        off = voff
        # optional [0] version
        if off < end and der[off] == 0xA0:
            _, voff2, vlen2 = _der_read_tlv(der, off)
            off = voff2 + vlen2
        # serial INTEGER, signature SEQUENCE, issuer Name
        for _ in range(3):
            _, voff, vlen = _der_read_tlv(der, off)
            off = voff + vlen
            if off > end:
                return None
        # validity SEQUENCE { notBefore Time, notAfter Time }
        tag, voff, _vlen = _der_read_tlv(der, off)
        if tag != 0x30:
            return None
        off = voff
        text = None
        for _ in range(2):
            tag2, voff2, vlen2 = _der_read_tlv(der, off)
            raw = bytes(der[voff2:voff2 + vlen2])
            off = voff2 + vlen2
            if tag2 == 0x17 and len(raw) >= 13:
                year = int(raw[0:2])
                year += 2000 if year < 50 else 1900
                text = "%04d-%s-%sT%s:%s:%s" % (
                    year, raw[2:4].decode(), raw[4:6].decode(),
                    raw[6:8].decode(), raw[8:10].decode(),
                    raw[10:12].decode())
            elif tag2 == 0x18 and len(raw) >= 14:
                text = "%s-%s-%sT%s:%s:%s" % (
                    raw[0:4].decode(), raw[4:6].decode(),
                    raw[6:8].decode(), raw[8:10].decode(),
                    raw[10:12].decode(), raw[12:14].decode())
        if text is None:
            return None
        try:
            when = time.strptime(text, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
        import calendar
        return float(calendar.timegm(when))
    except (ValueError, IndexError, UnicodeDecodeError):
        return None


def cert_days_left(not_after, now):
    # type: (str, float) -> object
    """Whole days from `now` until a certificate notAfter string.

    Pure date math (isolated for tests); None when unparseable.
    """
    try:
        expires = ssl.cert_time_to_seconds(not_after)
    except ValueError:
        return None
    return int((expires - now) // 86400)


# ---------------------------------------------------------------------------
# Document-root checks (fd-relative, never following symlinks)
# ---------------------------------------------------------------------------

def open_dir(abs_path, expect, hrel, summary):
    # type: (str, object, str, dict) -> object
    """Open a directory O_NOFOLLOW with (dev, ino) verification."""
    try:
        fd = os.open(abs_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        if pe._is_resource_error(exc):
            raise pe.ResourceLimitError(
                "too many open files while opening %s: %s" % (hrel, exc))
        summary["counts"]["errors"] += 1
        _add_capped(summary, "errors",
                    {"path": hrel,
                     "reason": "cannot open directory: %s" % exc})
        return None
    if expect is not None:
        try:
            fst = os.fstat(fd)
        except OSError as exc:
            os.close(fd)
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": hrel,
                         "reason": "cannot stat directory: %s" % exc})
            return None
        if (fst.st_dev, fst.st_ino) != expect:
            os.close(fd)
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": hrel,
                         "reason": "directory changed during walk; skipped"})
            return None
    return fd


def read_capped_at(dir_fd, name, cap):
    # type: (int, str, int) -> object
    """Bytes of a regular file via O_NOFOLLOW open, capped; None on failure."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                      dir_fd=dir_fd)
    except OSError:
        return None
    try:
        try:
            size = os.fstat(fd).st_size
            if size > cap:
                os.lseek(fd, size - cap, os.SEEK_SET)
        except OSError:
            return None
        chunks = []
        remaining = cap + 1
        while remaining > 0:
            try:
                data = os.read(fd, min(65536, remaining))
            except OSError:
                return None
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        return b"".join(chunks)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def tail_lines(blob, count):
    # type: (bytes, int) -> list
    """Last `count` text lines of a byte blob (errors replaced)."""
    text = blob.decode("utf-8", errors="replace")
    return text.splitlines()[-count:]


def check_docroot(fd, hrel, uid, top_dev):
    # type: (int, str, int, int) -> dict
    """Directory, mode and index facts for one open docroot."""
    try:
        st = os.fstat(fd)
    except OSError as exc:
        return {"exists": True, "is_dir": True, "error": str(exc)}
    out = {"exists": True, "is_dir": True,
           "mode": "%04o" % (stat.S_IMODE(st.st_mode)),
           "owner_ok": st.st_uid == uid}
    try:
        names = sorted(os.listdir(fd))
    except OSError as exc:
        out["error"] = "cannot list: %s" % exc
        return out
    out["index"] = None
    for cand in INDEX_NAMES:
        if cand in names:
            out["index"] = cand
            break
    out["names"] = names
    return out


def read_htaccess(fd):
    # type: (int) -> object
    """Full .htaccess bytes via O_NOFOLLOW, capped; None when absent."""
    try:
        st = os.stat(".htaccess", dir_fd=fd, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    return read_capped_at(fd, ".htaccess", HTACCESS_MAX_BYTES)


HT_BEGIN_MARKER = "# BEGIN UserTools"
HT_END_MARKER = "# END UserTools"


def analyse_htaccess(blob):
    # type: (bytes) -> dict
    """Flag lines that break under PHP-FPM plus rewrite oddities.

    Only unguarded php_value/php_flag lines count: cPanel wraps its own
    in <IfModule phpX_module>/<IfModule lsapi_module> blocks, which Apache
    skips when PHP runs as FPM, so those never 500. A negated guard
    (<IfModule !...>) does not protect (its body runs exactly when the
    module is absent), so lines under one still count.
    """
    lines = blob.decode("utf-8", errors="replace").splitlines()
    php_lines = []
    has_rewrite = False
    has_engine = False
    marker = False
    guards = []  # type: list
    for num, line in enumerate(lines, 1):
        code = line.split("#", 1)[0]
        m = re.match(r"\s*</IfModule\b", code, re.IGNORECASE)
        if m:
            if guards:
                guards.pop()
        else:
            m = re.match(r"\s*<IfModule\s+(!?)\s*([\w:.-]+)\s*>", code,
                         re.IGNORECASE)
            if m:
                guards.append(bool(m.group(1)))
            else:
                stripped = code.strip()
                if not stripped.startswith("<"):
                    if re.match(r"php_(value|flag)\b", stripped,
                                re.IGNORECASE):
                        if not any(not neg for neg in guards):
                            php_lines.append(num)
                    if re.search(r"Rewrite(?:Rule|Cond)\b", stripped,
                                 re.IGNORECASE):
                        has_rewrite = True
                    if re.match(r"RewriteEngine\s+On\b", stripped,
                                re.IGNORECASE):
                        has_engine = True
        if line.strip() == HT_BEGIN_MARKER:
            marker = True
    return {"present": True,
            "php_value_lines": php_lines,
            "missing_rewrite_engine": has_rewrite and not has_engine,
            "marker": marker}


def redirect_source_line(code):
    # type: (str) -> bool
    """True for a line that can send a request to another URL."""
    stripped = code.strip()
    if not stripped or stripped.startswith("#"):
        return False
    if re.match(r"Redirect(?:Match|Permanent|Temp)?\b",
                stripped, re.IGNORECASE):
        return True
    if re.match(r"RewriteCond\b", stripped, re.IGNORECASE) \
            and re.search(
                r"%\{(?:HTTPS|SERVER_PORT|HTTP:X-Forwarded-Proto)\}",
                stripped, re.IGNORECASE):
        return True
    if re.match(r"RewriteRule\b", stripped, re.IGNORECASE):
        fields = stripped.split()
        if len(fields) >= 3:
            target = fields[2].strip("\"'")
            if re.match(r"https?://", target, re.IGNORECASE):
                return True
        for match in re.finditer(r"\[([^\]]*)\]", stripped):
            for flag in match.group(1).split(","):
                flag = flag.strip().upper()
                if flag == "R" or flag.startswith("R="):
                    return True
    return False

# ---------------------------------------------------------------------------
# Doctor scan: one fact record per website
# ---------------------------------------------------------------------------

class Checker(object):
    """Per-domain fact gathering with a shared deadline."""

    def __init__(self, home, uid, summary, progress_cb, deadline,
                 progress_every, top_dev, timeout, https_port=HTTPS_PORT,
                 domains=None):
        # type: (str, int, dict, object, object, int, int, float, int, object) -> None
        self.home = home
        self.uid = uid
        self.summary = summary
        self.progress_cb = progress_cb
        self.deadline = deadline
        self.progress_every = progress_every
        self.top_dev = top_dev
        self.timeout = timeout
        self.https_port = https_port
        self.domains = domains
        self.done = 0

    def poll(self):
        # type: () -> None
        self.summary["counts"]["scanned"] = self.done
        if self.progress_every > 0 and self.done % self.progress_every == 0:
            self.progress_cb(self.done, self.summary)
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.summary["timed_out"] = True
            raise _WalkDone()
        if pe.stop_requested():
            self.summary["interrupted"] = True
            raise _WalkDone()

    def check_one(self, target):
        # type: (dict) -> dict
        """Collect every fact for one website (never raises)."""
        domain = target["domain"]
        self.done += 1
        self.poll()
        rec = {"domain": domain, "deferred": False,
               "php": {"version": target.get("php"),
                       "fpm": target.get("fpm")}}
        docroot = self.check_docroot(target)
        rec["docroot"] = docroot
        if docroot.get("usable"):
            rec["http"] = http_chain(
                target["ip"], target["port"], domain, "/", self.timeout,
                self.https_port)
            if rec["http"].get("verdict") == "loop":
                rec["http"]["sources"] = self.redirect_sources(
                    docroot["hrel"])
            rec["htaccess"] = self.check_htaccess(
                docroot["abs"], docroot["hrel"])
            rec["logs"] = self.check_logs(domain, docroot["abs"],
                                          docroot["hrel"])
            rec["xmlrpc"] = self.check_xmlrpc(target, docroot)
        else:
            rec["http"] = {"status": 0, "location": None, "ms": None,
                           "length": None, "exposed": False,
                           "error": "docroot unusable"}
            rec["htaccess"] = {"present": False}
            rec["logs"] = {}
            rec["xmlrpc"] = {"wp": False, "jetpack": False, "probe": None,
                             "state": None, "reason": None}
        rec["ssl"] = tls_expiry(target["ip"], domain, self.timeout)
        return rec

    def check_docroot(self, target):
        # type: (dict) -> dict
        """Validate the docroot and gather mode/index facts."""
        real = os.path.realpath(target["docroot"])
        hrel = pe.home_relpath(real, self.home)
        if real != self.home and os.path.commonpath([self.home, real]) != self.home:
            return {"usable": False, "reason": "outside the home folder"}
        if pe.is_protected_entry(hrel):
            return {"usable": False, "reason": "inside a protected path"}
        try:
            st = os.lstat(real)
        except OSError:
            return {"usable": False, "reason": "missing"}
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            return {"usable": False, "reason": "not a directory"}
        if st.st_uid != self.uid or st.st_dev != self.top_dev:
            return {"usable": False, "reason": "not yours"}
        fd = open_dir(real, (st.st_dev, st.st_ino), hrel, self.summary)
        if fd is None:
            return {"usable": False, "reason": "cannot open"}
        try:
            facts = check_docroot(fd, hrel, self.uid, self.top_dev)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        facts["usable"] = True
        facts["abs"] = real
        facts["hrel"] = hrel
        return facts

    def check_htaccess(self, abs_root, hrel):
        # type: (str, str) -> dict
        """Read and analyse the docroot .htaccess (capped)."""
        fd = open_dir(abs_root, None, hrel, self.summary)
        if fd is None:
            return {"present": False, "error": "cannot open docroot"}
        try:
            blob = read_htaccess(fd)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        if blob is None:
            return {"present": False}
        return analyse_htaccess(blob)

    def read_dir_htaccess(self, hrel):
        # type: (str) -> object
        """Read one .htaccess from a real, owned directory inside home."""
        full = self.home if hrel == "." else os.path.join(self.home, hrel)
        try:
            st = os.lstat(full)
        except OSError:
            return None
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                or st.st_uid != self.uid or st.st_dev != self.top_dev:
            return None
        try:
            fd = os.open(full, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            return None
        try:
            try:
                fst = os.fstat(fd)
            except OSError:
                return None
            if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) \
                    or fst.st_uid != self.uid or not stat.S_ISDIR(fst.st_mode):
                return None
            return read_htaccess(fd)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def redirect_sources(self, docroot_hrel):
        # type: (str) -> list
        """Redirect-related .htaccess lines from the docroot up to home.

        Read-only and capped. Symlinks, other owners, other filesystems
        and anything above the home are never read. Each entry is
        {file, line, text}; the file is home-relative.
        """
        out = []
        rel = docroot_hrel
        while True:
            blob = self.read_dir_htaccess(rel)
            if blob is not None:
                text = blob.decode("utf-8", errors="replace")
                for num, line in enumerate(text.splitlines(), 1):
                    if not redirect_source_line(line):
                        continue
                    name = ".htaccess" if rel == "." else rel + "/.htaccess"
                    out.append({"file": name, "line": num,
                                "text": line.strip()})
                    if len(out) >= MAX_REDIRECT_SOURCES:
                        return out
            if rel == ".":
                return out
            rel = rel.rsplit("/", 1)[0] if "/" in rel else "."

    def check_logs(self, domain, abs_root, hrel):
        # type: (str, str, str) -> dict
        """Last lines of the docroot and per-domain PHP error logs."""
        out = {}
        fd = open_dir(abs_root, None, hrel, self.summary)
        if fd is not None:
            try:
                names = sorted(os.listdir(fd))
            except OSError:
                names = []
            try:
                os.close(fd)
            except OSError:
                pass
            if "error_log" in names:
                blob = self.read_named(abs_root, hrel, "error_log")
                if blob is not None:
                    out["docroot_log"] = tail_lines(blob, LOG_TAIL_LINES)
        per_domain = domain.replace(".", "_") + ".php.error.log"
        blob = self.read_named(os.path.join(self.home, "logs"), "logs",
                               per_domain)
        if blob is not None:
            out["php_log"] = tail_lines(blob, LOG_TAIL_LINES)
        return out

    def check_xmlrpc(self, target, docroot):
        # type: (dict, dict) -> dict
        """WordPress xmlrpc.php facts: served or not, Jetpack or not.

        wp is true when the docroot holds xmlrpc.php or wp-config.php as
        a regular file (symlinks never count). jetpack is true when
        wp-content/plugins/jetpack is a real directory. Only WordPress
        sites are probed, over HTTP exactly like an exposed file (same
        literal IP, same redirect rules, HEAD then capped GET, never a
        POST); state/reason come from finding_state, so redirects, failed
        hops and server errors never read as safe.
        """
        out = {"wp": False, "jetpack": False, "probe": None,
               "state": None, "reason": None}  # type: dict
        fd = open_dir(docroot["abs"], None, docroot["hrel"], self.summary)
        if fd is None:
            return out
        try:
            if self._is_reg_file(fd, "xmlrpc.php") \
                    or self._is_reg_file(fd, "wp-config.php"):
                out["wp"] = True
            out["jetpack"] = self._has_jetpack(fd, docroot["hrel"])
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        if not out["wp"]:
            return out
        probe = http_probe(target["ip"], target["port"], target["domain"],
                           "/xmlrpc.php", self.timeout, self.https_port,
                           self.domains)
        state, reason = finding_state(probe)
        out["probe"] = probe
        out["state"] = state
        out["reason"] = reason
        return out

    @staticmethod
    def _is_reg_file(dir_fd, name):
        # type: (int, str) -> bool
        """True when name is a regular file (symlinks never count)."""
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISREG(st.st_mode)

    def _has_jetpack(self, docroot_fd, hrel):
        # type: (int, str) -> bool
        """True when wp-content/plugins/jetpack is a real directory.

        Each level opens O_NOFOLLOW, so a symlinked wp-content or
        plugins tree never counts as an installed plugin.
        """
        try:
            wfd = os.open("wp-content",
                          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=docroot_fd)
        except OSError as exc:
            if pe._is_resource_error(exc):
                raise pe.ResourceLimitError(
                    "too many open files while checking %s: %s"
                    % (hrel, exc))
            return False
        try:
            try:
                pfd = os.open("plugins",
                              os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=wfd)
            except OSError as exc:
                if pe._is_resource_error(exc):
                    raise pe.ResourceLimitError(
                        "too many open files while checking %s: %s"
                        % (hrel, exc))
                return False
            try:
                try:
                    st = os.stat("jetpack", dir_fd=pfd,
                                 follow_symlinks=False)
                except OSError:
                    return False
                return stat.S_ISDIR(st.st_mode)
            finally:
                try:
                    os.close(pfd)
                except OSError:
                    pass
        finally:
            try:
                os.close(wfd)
            except OSError:
                pass

    def read_named(self, abs_dir, hrel, name):
        # type: (str, str, str) -> object
        """Capped tail bytes of one regular owned file; None when absent."""
        try:
            dst = os.lstat(abs_dir)
        except OSError:
            return None
        if not stat.S_ISDIR(dst.st_mode) or stat.S_ISLNK(dst.st_mode):
            return None
        if dst.st_uid != self.uid or dst.st_dev != self.top_dev:
            return None
        fd = open_dir(abs_dir, (dst.st_dev, dst.st_ino), hrel, self.summary)
        if fd is None:
            return None
        try:
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                return None
            if not stat.S_ISREG(st.st_mode) or st.st_uid != self.uid:
                return None
            return read_capped_at(fd, name, LOG_TAIL_BYTES)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass


def doctor_scan(home, uid, summary, progress_cb, deadline, progress_every,
                top_dev, timeout, targets, https_port=HTTPS_PORT):
    # type: (str, int, dict, object, object, int, int, float, list, int) -> list
    """Fact records for up to MAX_DOMAINS websites inside the budget."""
    domains = set()
    for target in targets:
        if isinstance(target.get("domain"), str):
            domains.add(target["domain"].lower())
    checker = Checker(home, uid, summary, progress_cb, deadline,
                      progress_every, top_dev, timeout, https_port,
                      domains)
    records = []
    for pos, target in enumerate(targets[:MAX_DOMAINS]):
        if deadline is not None and time.monotonic() >= deadline:
            summary["timed_out"] = True
            for rest in targets[pos:MAX_DOMAINS]:
                records.append({"domain": rest["domain"], "deferred": True,
                                "reason": "time budget exhausted"})
            break
        try:
            records.append(checker.check_one(target))
        except _WalkDone:
            for rest in targets[pos + 1:MAX_DOMAINS]:
                records.append({"domain": rest["domain"], "deferred": True,
                                "reason": "time budget exhausted"})
            break
        except Exception as exc:  # defensive: one bad domain never kills the run
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": target.get("domain", "?"),
                         "reason": "check failed: %s" % exc})
    for target in targets[MAX_DOMAINS:]:
        records.append({"domain": target["domain"], "deferred": True,
                        "reason": "more than %d domains" % MAX_DOMAINS})
    return records
# ---------------------------------------------------------------------------
# Exposed-file scan: walk docroots, probe each risky name over HTTP
# ---------------------------------------------------------------------------

def classify_exposed(base, is_dir):
    # type: (str, bool) -> object
    """Kind of exposed-file risk, or None when the name is innocent."""
    if is_dir:
        if base == ".git":
            return "git_dir"
        return None
    low = base.lower()
    if low == ".env" or low.startswith(".env."):
        return "env_copy"
    if base.startswith("wp-config.php.") and len(base) > len("wp-config.php."):
        return "wp_config_copy"
    if low in ("phpinfo.php", "info.php"):
        return "phpinfo"
    if low.startswith("adminer") and low.endswith(".php"):
        return "adminer"
    if base.endswith("~"):
        return "backup_tilde"
    if base.endswith(".bak"):
        return "backup_bak"
    if EXPOSED_SQL_RE.search(base):
        return "sql_dump"
    if EXPOSED_ARCHIVE_RE.search(base):
        return "archive"
    if low.endswith(".log"):
        return "log_file"
    return None


def probe_path_for(domain_rel, kind):
    # type: (str, str) -> str
    """URL path to probe for a finding (dirs probe their HEAD file)."""
    if kind == "git_dir":
        return domain_rel + "/HEAD"
    return domain_rel


def is_blockable_name(text):
    # type: (object) -> bool
    """True when text may be embedded in a .htaccess deny rule.

    Only printable ASCII without `"`, `'`, backslash, backtick, `%` or
    `$`: a quote would close the rule's quoting and a newline would
    write extra lines, either of which makes Apache reject the whole
    file (site down). Inside an <If> expression `%{NAME}` is variable
    interpolation and `$0`..`$9` are regex back-references, even in
    single quotes, so those names are Move-only too. Anything else is
    moved, never blocked.
    """
    if not text or not isinstance(text, str):
        return False
    for ch in text:
        if ch in "\"'\\`%$":
            return False
        if ord(ch) < 0x20 or ord(ch) > 0x7E:
            return False
    return True


def finding_state(probe):
    # type: (dict) -> tuple
    """(state, reason) for a probe: "exposed", "not_exposed", or
    "not_checked". Only 401/403/404/410 count as safe; redirects,
    failed HTTPS hops and server errors are "not checked" with the
    reason spelled out, never a clean bill of health.
    """
    if probe.get("exposed"):
        return ("exposed", None)
    status = probe.get("status") or 0
    if status in (401, 403, 404, 410):
        return ("not_exposed", None)
    if status in (301, 302, 303, 307, 308):
        location = probe.get("location") or "elsewhere"
        if probe.get("error"):
            return ("not_checked",
                    "redirects to %s (%s)" % (location, probe["error"]))
        return ("not_checked", "redirects to %s" % location)
    if status >= 500:
        return ("not_checked", "server error %d" % status)
    if status == 0:
        err = probe.get("error") or "no answer"
        return ("not_checked", "not checked: %s" % err)
    return ("not_checked", "unexpected status %d" % status)


class ExposedWalker(object):
    """Depth-capped docroot walker that collects + probes risky names."""

    def __init__(self, home, uid, summary, progress_cb, deadline,
                 progress_every, top_dev, timeout, ip, port, domain,
                 https_port=HTTPS_PORT, alt_hosts=None):
        # type: (str, int, dict, object, object, int, int, float, str, int, str, int, object) -> None
        self.home = home
        self.uid = uid
        self.summary = summary
        self.progress_cb = progress_cb
        self.deadline = deadline
        self.progress_every = progress_every
        self.top_dev = top_dev
        self.timeout = timeout
        self.ip = ip
        self.port = port
        self.domain = domain
        self.https_port = https_port
        self.alt_hosts = alt_hosts
        self.done = 0
        self.findings = []  # type: list

    def poll(self):
        # type: () -> None
        self.summary["counts"]["scanned"] = self.done
        if self.progress_every > 0 and self.done % self.progress_every == 0:
            self.progress_cb(self.done, self.summary)
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.summary["timed_out"] = True
            raise _WalkDone()
        if pe.stop_requested():
            self.summary["interrupted"] = True
            raise _WalkDone()

    def record_skip(self, kind, hrel, reason=None):
        # type: (str, str, object) -> None
        self.summary["counts"][kind] += 1
        entry = {"path": hrel}  # type: dict
        if reason is not None:
            entry["reason"] = reason
        _add_capped(self.summary, kind, entry)

    def examine(self, dir_fd, name, hrel, rrel):
        # type: (int, str, str, str) -> tuple
        """Classify one entry; ("dir", st) to descend, else ("skip", None).

        hrel is home-relative (filesystem + quarantine layout); rrel is
        docroot-relative (HTTP probe URLs + finding display).
        """
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError as exc:
            if pe._is_resource_error(exc):
                raise pe.ResourceLimitError(
                    "too many open files while examining %s: %s" % (hrel, exc))
            self.summary["counts"]["errors"] += 1
            _add_capped(self.summary, "errors",
                        {"path": hrel, "reason": "cannot stat: %s" % exc})
            return ("skip", None)
        self.done += 1
        self.poll()
        if stat.S_ISLNK(st.st_mode):
            self.record_skip("skipped_symlink", hrel)
            return ("skip", None)
        if st.st_dev != self.top_dev:
            self.record_skip("skipped_xdev", hrel)
            return ("skip", None)
        if stat.S_ISDIR(st.st_mode):
            if st.st_uid != self.uid:
                self.summary["counts"]["not_owned"] += 1
                _add_capped(self.summary, "not_owned",
                            {"path": hrel, "owner": pe.owner_name(st.st_uid)})
                return ("skip", None)
            return ("dir", st)
        if not stat.S_ISREG(st.st_mode):
            self.record_skip("skipped_special", hrel)
            return ("skip", None)
        if st.st_uid != self.uid:
            self.summary["counts"]["not_owned"] += 1
            _add_capped(self.summary, "not_owned",
                        {"path": hrel, "owner": pe.owner_name(st.st_uid)})
            return ("skip", None)
        if st.st_nlink != 1:
            self.record_skip("skipped_hardlink", hrel,
                             "more than one hard link; left alone")
            return ("skip", None)
        kind = classify_exposed(name, False)
        if kind is not None:
            self.probe_finding(hrel, rrel, kind, st.st_size)
        return ("skip", None)

    def probe_finding(self, hrel, rrel, kind, size):
        # type: (str, str, str, object) -> None
        """HTTP-probe one candidate; record it with its verdict.

        exposed means the server served the bytes (200/206). confidence
        is "confirmed" only when the served length matches the file size
        on disk (known sizes only); anything else downloadable is
        "likely", since front controllers often answer 200 for any
        path (soft 404). blockable is false for names that can never
        appear in a .htaccess rule; those are moved, never blocked.
        state is "exposed", "not_exposed" (401/403/404/410 only), or
        "not_checked" with a reason: redirects, failed HTTPS hops and
        server errors never read as safe.
        """
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.summary["counts"]["errors"] += 1
            _add_capped(self.summary, "errors",
                        {"path": hrel, "reason": "probe budget exhausted"})
            return
        url_path = "/" + probe_path_for(rrel, kind)
        probe = http_probe(self.ip, self.port, self.domain, url_path,
                           self.timeout, self.https_port, self.alt_hosts)
        self.summary["counts"]["probed"] += 1
        if probe["exposed"]:
            self.summary["counts"]["exposed"] += 1
        confidence = None
        if probe["exposed"]:
            if probe["length"] is not None and size is not None \
                    and probe["length"] == size:
                confidence = "confirmed"
            else:
                confidence = "likely"
        state, reason = finding_state(probe)
        if state == "not_checked":
            self.summary["counts"]["not_checked"] += 1
        self.findings.append({
            "domain": self.domain,
            "relpath": hrel,
            "urlpath": url_path,
            "kind": kind,
            "size": size,
            "http_status": probe["status"],
            "http_length": probe["length"],
            "exposed": probe["exposed"],
            "scheme": probe.get("scheme", "http"),
            "confidence": confidence,
            "state": state,
            "reason": reason,
            "blockable": is_blockable_name(hrel)
            and is_blockable_name(url_path),
        })

    def walk_open(self, fd, hrel, rrel, depth):
        # type: (int, str, str, int) -> None
        """List one open directory; descend to SCAN_MAX_DEPTH."""
        try:
            names = sorted(os.listdir(fd))
        except OSError as exc:
            if pe._is_resource_error(exc):
                raise pe.ResourceLimitError(
                    "too many open files while listing %s: %s" % (hrel, exc))
            self.summary["counts"]["errors"] += 1
            _add_capped(self.summary, "errors",
                        {"path": hrel,
                         "reason": "cannot list directory: %s" % exc})
            return
        pending = []
        for name in names:
            child = hrel + "/" + name if hrel != "." else name
            rchild = rrel + "/" + name if rrel else name
            kind, st = self.examine(fd, name, child, rchild)
            if kind == "dir":
                if depth < pe.SCAN_MAX_DEPTH:
                    pending.append((child, st, rchild))
        for child, st, rchild in pending:
            # A .git folder itself is the finding; probe it through HEAD.
            # The walk still descends (config/objects are innocent names).
            if child.rsplit("/", 1)[-1] == ".git":
                self.probe_git_dir(child, rchild)
            sub = open_dir(os.path.join(self.home, child),
                            (st.st_dev, st.st_ino), child, self.summary)
            if sub is None:
                continue
            try:
                self.walk_open(sub, child, rchild, depth + 1)
            finally:
                try:
                    os.close(sub)
                except OSError:
                    pass

    def probe_git_dir(self, hrel, rrel):
        # type: (str, str) -> None
        """Probe a .git folder through its HEAD file.

        The HEAD size on disk feeds the confirmed/likely verdict the
        same way file sizes do; when HEAD cannot be statted the size
        stays unknown and a served HEAD is only "likely".
        """
        size = None
        try:
            st = os.stat(os.path.join(self.home, hrel, "HEAD"))
        except OSError:
            st = None
        if st is not None and stat.S_ISREG(st.st_mode) \
                and st.st_uid == self.uid and st.st_dev == self.top_dev:
            size = st.st_size
        self.probe_finding(hrel, rrel, "git_dir", size)


def exposed_scan(home, uid, summary, progress_cb, deadline, progress_every,
                 top_dev, timeout, targets, https_port=HTTPS_PORT):
    # type: (str, int, dict, object, object, int, int, float, list, int) -> list
    """Walk every docroot and probe each risky name (10-domain budget)."""
    domains = set()
    for target in targets:
        if isinstance(target.get("domain"), str):
            domains.add(target["domain"].lower())
    findings = []
    for pos, target in enumerate(targets[:MAX_DOMAINS]):
        if deadline is not None and time.monotonic() >= deadline:
            summary["timed_out"] = True
            for rest in targets[pos:MAX_DOMAINS]:
                summary["counts"]["errors"] += 1
                _add_capped(summary, "errors",
                            {"path": rest["domain"],
                             "reason": "time budget exhausted"})
            break
        real = os.path.realpath(target["docroot"])
        hrel = pe.home_relpath(real, home)
        if real != home and os.path.commonpath([home, real]) != home:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": target["domain"],
                         "reason": "docroot outside the home folder"})
            continue
        try:
            st = os.lstat(real)
        except OSError:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": target["domain"],
                         "reason": "docroot missing"})
            continue
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": target["domain"],
                         "reason": "docroot is not a directory"})
            continue
        if st.st_uid != uid or st.st_dev != top_dev:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": target["domain"],
                         "reason": "docroot is not yours"})
            continue
        walker = ExposedWalker(home, uid, summary, progress_cb, deadline,
                              progress_every, top_dev, timeout,
                              target["ip"], target["port"],
                              target["domain"], https_port, domains)
        fd = open_dir(real, (st.st_dev, st.st_ino), hrel, summary)
        if fd is None:
            continue
        try:
            walker.walk_open(fd, hrel, "", 0)
        except _WalkDone:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        findings.extend(walker.findings)
    for target in targets[MAX_DOMAINS:]:
        summary["counts"]["errors"] += 1
        _add_capped(summary, "errors",
                    {"path": target["domain"],
                     "reason": "more than %d domains" % MAX_DOMAINS})
    findings.sort(key=lambda f: (f["domain"], f["relpath"]))
    for i, found in enumerate(findings, 1):
        found["id"] = "f%d" % i
    return findings
# ---------------------------------------------------------------------------
# Quarantine: move findings out of the public folder, restore them back
# ---------------------------------------------------------------------------

def _ensure_dir_0700(path, stop):
    # type: (str, str) -> None
    """Create a directory tree; levels at/below `stop` end up 0700."""
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise pe.UsageError("cannot create directory %r: %s" % (path, exc))
    head = path
    while True:
        if os.path.isdir(head) and not os.path.islink(head):
            try:
                os.chmod(head, 0o700)
            except OSError:
                pass
        if head == stop:
            break
        parent = os.path.dirname(head)
        if parent == head or not parent or len(parent) < len(stop):
            break
        head = parent


def job_result_path(home, job_id):
    # type: (str, str) -> str
    """Server-side job result file; UsageError on a bad id."""
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,64}$", job_id or ""):
        raise pe.UsageError("unknown job")
    path = os.path.join(home, ".cpanel", "usertools", "jobs",
                        job_id + ".result.json")
    try:
        dst = os.lstat(path)
    except OSError:
        raise pe.UsageError("unknown job")
    if not stat.S_ISREG(dst.st_mode) or stat.S_ISLNK(dst.st_mode):
        raise pe.UsageError("unknown job")
    return path


def load_findings(home, job_id):
    # type: (str, str) -> list
    """Findings recorded by a finished exposed scan (server-side only)."""
    try:
        with open(job_result_path(home, job_id), "r",
                  encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError) as exc:
        raise pe.UsageError("cannot read scan job: %s" % exc)
    if not isinstance(payload, dict):
        raise pe.UsageError("scan job is unreadable")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise pe.UsageError("scan job has no findings")
    return findings


def resolve_finding(home, job_id, finding_id):
    # type: (str, str, str) -> dict
    """One finding from a scan job; validated id, home-confined path."""
    if not re.match(r"^[a-z0-9]{1,16}$", finding_id or ""):
        raise pe.UsageError("unknown finding")
    for found in load_findings(home, job_id):
        if isinstance(found, dict) and found.get("id") == finding_id:
            try:
                rel = pe.validate_home_rel(found.get("relpath", ""))
            except pe.UsageError as exc:
                raise pe.UsageError("finding path refused: %s" % exc)
            if not rel or rel == ".":
                raise pe.UsageError("finding path refused")
            found = dict(found)
            found["relpath"] = rel
            return found
    raise pe.UsageError("unknown finding")


def quarantine_batch(home):
    # type: (str) -> str
    """Create (and return) a fresh quarantine batch directory."""
    root = quarantine_dir(home)
    _ensure_dir_0700(root, root)
    for _ in range(100):
        name = sclean.new_batch_id()
        full = os.path.join(root, name)
        try:
            os.mkdir(full, 0o700)
        except FileExistsError:
            time.sleep(1)
            continue
        except OSError as exc:
            raise pe.UsageError("cannot create quarantine batch: %s" % exc)
        os.chmod(full, 0o700)
        return full
    raise pe.UsageError("cannot create quarantine batch: clock stuck")


def quarantine_move(home, uid, summary, finding):
    # type: (str, int, dict, dict) -> None
    """Move one finding out of the public folder (file or .git dir)."""
    hrel = finding["relpath"]
    src = os.path.join(home, hrel)
    try:
        now = os.lstat(src)
    except OSError as exc:
        raise pe.UsageError("lost race on %s: %s" % (hrel, exc))
    if stat.S_ISLNK(now.st_mode):
        raise pe.UsageError("%s is a link; left alone" % hrel)
    if not (stat.S_ISREG(now.st_mode) or stat.S_ISDIR(now.st_mode)):
        raise pe.UsageError("%s is not movable; left alone" % hrel)
    if now.st_uid != uid or now.st_dev != top_dev(home):
        raise pe.UsageError("%s changed during the run; left alone" % hrel)
    if stat.S_ISREG(now.st_mode) and now.st_nlink != 1:
        raise pe.UsageError("%s changed during the run; left alone" % hrel)
    batch_path = quarantine_batch(home)
    dst = os.path.join(batch_path, hrel)
    _ensure_dir_0700(os.path.dirname(dst), batch_path)
    if os.path.lexists(dst):
        raise pe.UsageError("%s is already quarantined" % hrel)
    os.rename(src, dst)
    sclean.write_manifest(batch_path, [{
        "path": hrel,
        "size": now.st_size,
        "mode": "%04o" % (stat.S_IMODE(now.st_mode)),
        "mtime": now.st_mtime,
    }])
    summary["counts"]["moved"] += 1
    summary["counts"]["changed"] += 1
    _add_capped(summary, "moved", {"path": hrel})
    summary["quarantine_batch"] = os.path.basename(batch_path)


def top_dev(home):
    # type: (str) -> int
    try:
        return os.stat(home).st_dev
    except OSError as exc:
        raise pe.UsageError("cannot stat home: %s" % exc)


def quarantine_restore_batch(home, uid, summary, batch):
    # type: (str, int, dict, str) -> None
    """Put a whole quarantine batch back; conflicts reported, never overwritten."""
    parse_batch_id(batch)
    root = os.path.join(quarantine_dir(home), batch)
    try:
        dst = os.lstat(root)
    except OSError:
        raise pe.UsageError("unknown quarantine batch: %s" % batch)
    if not stat.S_ISDIR(dst.st_mode) or stat.S_ISLNK(dst.st_mode):
        raise pe.UsageError("unknown quarantine batch: %s" % batch)
    if dst.st_uid != uid:
        raise pe.UsageError("quarantine batch is not yours; left alone")
    entries = sclean.read_manifest(root)
    restored = 0
    remaining = []
    for ent in entries:
        hrel = ent["path"]
        try:
            if _restore_quarantined(home, uid, summary, root, hrel):
                restored += 1
            else:
                remaining.append(ent)
        except pe.UsageError as exc:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": hrel, "reason": str(exc)})
            remaining.append(ent)
        except OSError as exc:
            summary["counts"]["errors"] += 1
            _add_capped(summary, "errors",
                        {"path": hrel, "reason": "cannot restore: %s" % exc})
            remaining.append(ent)
    summary["counts"]["restored"] = restored
    summary["counts"]["changed"] = restored
    if remaining:
        sclean.write_manifest(root, remaining)
    else:
        try:
            os.unlink(os.path.join(root, "manifest.json"))
        except OSError:
            pass
        remove_empty_dirs(root)


def _restore_quarantined(home, uid, summary, root, hrel):
    # type: (str, int, dict, str, str) -> bool
    """Restore one quarantined path; True when it came back."""
    src = os.path.join(root, hrel)
    dst_path = os.path.join(home, hrel)
    try:
        st = os.lstat(src)
    except OSError as exc:
        raise pe.UsageError("lost in quarantine: %s" % exc)
    if stat.S_ISLNK(st.st_mode) or st.st_uid != uid:
        raise pe.UsageError("quarantine copy changed; left in quarantine")
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise pe.UsageError("quarantine copy changed; left in quarantine")
    if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
        raise pe.UsageError("quarantine copy changed; left in quarantine")
    sclean_ensure_parents(home, hrel)
    if stat.S_ISDIR(st.st_mode):
        if os.path.lexists(dst_path):
            summary["counts"]["restore_conflicts"] += 1
            _add_capped(summary, "errors",
                        {"path": hrel,
                         "reason": "already exists; left the quarantine copy in place"})
            return False
        os.rename(src, dst_path)
        _add_capped(summary, "restored", {"path": hrel})
        return True
    try:
        os.link(src, dst_path)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            summary["counts"]["restore_conflicts"] += 1
            _add_capped(summary, "errors",
                        {"path": hrel,
                         "reason": "already exists; left the quarantine copy in place"})
            return False
        raise
    os.unlink(src)
    _add_capped(summary, "restored", {"path": hrel})
    return True


def sclean_ensure_parents(home, hrel):
    # type: (str, str) -> None
    """Create missing restore parents (0700); refuse blocked paths."""
    parent = os.path.dirname(hrel)
    if not parent:
        return
    cur = home
    for part in parent.split("/"):
        cur = os.path.join(cur, part)
        if os.path.lexists(cur):
            try:
                st = os.lstat(cur)
            except OSError as exc:
                raise pe.UsageError("%s is blocked: %s" % (hrel, exc))
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise pe.UsageError(
                    "%s is blocked by a non-directory; left in quarantine"
                    % hrel)
            continue
        try:
            os.mkdir(cur, 0o700)
        except OSError as exc:
            raise pe.UsageError("cannot recreate %s: %s" % (hrel, exc))


def remove_empty_dirs(root):
    # type: (str) -> None
    """Remove left-over empty folders under a batch, then the batch."""
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        if filenames:
            continue
        try:
            os.rmdir(dirpath)
        except OSError:
            pass
    try:
        os.rmdir(root)
    except OSError:
        pass
# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def parse_targets(values, want_php):
    # type: (object, bool) -> list
    """Clean repeatable --target flags; UsageError on the first bad one."""
    if not values:
        raise pe.UsageError("at least one --target is required")
    seen = []
    for value in values:
        target = parse_target(value, want_php)
        if target["domain"] in [t["domain"] for t in seen]:
            raise pe.UsageError("duplicate domain in --target: %s"
                                % target["domain"])
        seen.append(target)
    return seen


def build_parser():
    # type: () -> argparse.ArgumentParser
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--target", action="append", default=[],
                        help="website target D|R|I|P[|V|F] (repeatable)")
    parent.add_argument("--job", default=None,
                        help="scan job id (move only)")
    parent.add_argument("--finding", default=None,
                        help="finding id from the scan (move only)")
    parent.add_argument("--batch", default=None,
                        help="quarantine batch id (restore only)")
    parent.add_argument("--ip", default=None,
                        help="probe address, a literal IP (re-probe only)")
    parent.add_argument("--port", type=int, default=None,
                        help="probe port (re-probe only)")
    parent.add_argument("--host", default=None,
                        help="website name sent as Host (re-probe only)")
    parent.add_argument("--alt-host", action="append", default=[],
                        help="extra account hostname the probe may follow "
                             "a redirect to (re-probe only; repeatable)")
    parent.add_argument("--path", default=None,
                        help="URL path to probe, starting with / (re-probe only)")
    parent.add_argument("--timeout", type=float, default=REQUEST_TIMEOUT,
                        help="per-request seconds (default %s)"
                             % REQUEST_TIMEOUT)
    parent.add_argument("--https-port", type=int, default=HTTPS_PORT,
                        help="TLS port for the same-host HTTPS hop "
                             "(default %d)" % HTTPS_PORT)
    parent.add_argument("--budget", type=float, default=BUDGET_SECONDS,
                        help="total seconds for a scan (default %s)"
                             % BUDGET_SECONDS)
    parent.add_argument("--json-progress", default=None, metavar="FILE",
                        help="write progress JSON here every N entries")
    parent.add_argument("--progress-every", type=int,
                        default=pe.DEFAULT_PROGRESS_EVERY,
                        help="progress write interval (default %d)"
                             % pe.DEFAULT_PROGRESS_EVERY)
    parent.add_argument("--policy", default=None,
                        help="policy file (default %s if present)"
                             % pe.DEFAULT_POLICY_PATH)
    parent.add_argument("--lock-dir", default=None,
                        help="lock directory (default ~/.cpanel/usertools)")
    parent.add_argument("--home", default=None,
                        help="home directory for confinement checks "
                             "(test hook only; requires USERTOOLS_TESTING=1 "
                             "in the environment; default: your real home)")
    parser = argparse.ArgumentParser(
        prog="site_doctor.py",
        description="Unprivileged website checks inside your home directory.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor-scan", parents=[parent],
                   help="check homepages, docroots, TLS and logs")
    sub.add_parser("exposed-scan", parents=[parent],
                   help="find files that must never be public")
    sub.add_parser("exposed-move", parents=[parent],
                   help="quarantine one finding out of the public folder")
    sub.add_parser("exposed-restore", parents=[parent],
                   help="put a whole quarantine batch back")
    sub.add_parser("exposed-reprobe", parents=[parent],
                   help="probe one URL path and report status (no changes)")
    return parser


def main(argv=None):
    # type: (object) -> int
    pe.refuse_if_privileged()
    uid = os.getuid()

    try:
        signal.signal(signal.SIGTERM, pe._sigterm_handler)
    except (OSError, ValueError):
        pass  # no SIGTERM here; timeouts still bound the run

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.home is not None and \
            os.environ.get("USERTOOLS_TESTING") != "1":
        pe.eprint("error: --home is a test-only option")
        return pe.EXIT_USAGE

    try:
        home = pe.resolve_home(args.home)
        timeout = float(args.timeout)
        budget = float(args.budget)
        https_port = int(args.https_port)
        if timeout <= 0 or timeout > 60 or budget <= 0 or budget > 3600:
            raise pe.UsageError("bad --timeout/--budget range")
        if https_port < 1 or https_port > 65535:
            raise pe.UsageError("bad --https-port (want 1-65535)")
    except (pe.UsageError, ValueError) as exc:
        pe.eprint("error: %s" % exc)
        return pe.EXIT_USAGE

    pe.apply_resource_limits()

    policy = pe.load_policy(args.policy)
    limit = pe.max_job_seconds(policy)
    start = time.monotonic()
    deadline = start + min(limit, budget if args.command in
                           ("doctor-scan", "exposed-scan") else limit)

    lock_dir = args.lock_dir or os.path.join(home, ".cpanel", "usertools")
    lock = pe.JobLock(lock_dir)
    try:
        lock.acquire()
    except pe.BusyError as exc:
        pe.eprint("error: %s" % exc)
        return pe.EXIT_BUSY
    except pe.UsageError as exc:
        pe.eprint("error: %s" % exc)
        return pe.EXIT_USAGE

    acting = args.command not in ("doctor-scan", "exposed-scan")
    summary = new_clean_summary(args.command, home, not acting)

    progress_path = args.json_progress
    progress_every = args.progress_every if args.progress_every > 0 else 0

    def progress_cb(done, summ):
        # type: (int, dict) -> None
        if not progress_path:
            return
        pe.write_progress_file(progress_path, {
            "command": summ["command"],
            "scope": summ["scope"],
            "scanned": summ["counts"]["scanned"],
            "changed": summ["counts"]["changed"],
            "would_change": summ["counts"]["would_change"],
            "not_owned": summ["counts"]["not_owned"],
            "errors": summ["counts"]["errors"],
            "timed_out": summ["timed_out"],
            "interrupted": summ["interrupted"],
            "elapsed_seconds": round(time.monotonic() - start, 3),
        })

    def finish(code):
        # type: (int) -> int
        """Emit the JSON summary (partial on timeout/resource abort)."""
        summary["elapsed_seconds"] = round(time.monotonic() - start, 3)
        if progress_path:
            progress_cb(summary["counts"]["scanned"], summary)
        sys.stdout.write(json.dumps(summary, ensure_ascii=True, default=str,
                                    indent=2) + "\n")
        sys.stdout.flush()
        return code

    try:
        dev = top_dev(home)
        if args.command == "doctor-scan":
            targets = parse_targets(args.target, True)
            summary["domains"] = doctor_scan(
                home, uid, summary, progress_cb, deadline, progress_every,
                dev, timeout, targets, https_port)
        elif args.command == "exposed-scan":
            targets = parse_targets(args.target, False)
            summary["findings"] = exposed_scan(
                home, uid, summary, progress_cb, deadline, progress_every,
                dev, timeout, targets, https_port)
        elif args.command == "exposed-move":
            if not args.job or not args.finding:
                raise pe.UsageError("exposed-move needs --job and --finding")
            finding = resolve_finding(home, args.job, args.finding)
            quarantine_move(home, uid, summary, finding)
            summary["findings"] = [finding]
        elif args.command == "exposed-restore":
            if not args.batch:
                raise pe.UsageError("exposed-restore needs --batch")
            batch = parse_batch_id(args.batch)
            quarantine_restore_batch(home, uid, summary, batch)
        elif args.command == "exposed-reprobe":
            if not args.ip or not args.port or not args.host or not args.path:
                raise pe.UsageError(
                    "exposed-reprobe needs --ip, --port, --host and --path")
            try:
                socket.inet_pton(socket.AF_INET, args.ip)
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, args.ip)
                except OSError:
                    raise pe.UsageError("probe address must be a literal IP")
            if not 1 <= args.port <= 65535:
                raise pe.UsageError("bad probe port")
            if not args.path.startswith("/") or "\x00" in args.path \
                    or ".." in args.path.split("/"):
                raise pe.UsageError("bad probe path")
            if not re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$",
                            args.host):
                raise pe.UsageError("bad probe host")
            alt_hosts = []
            for extra in args.alt_host or []:
                if not re.match(
                        r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$",
                        extra):
                    raise pe.UsageError("bad --alt-host name")
                alt_hosts.append(extra)
            summary["probe"] = http_probe(args.ip, args.port, args.host,
                                          args.path, timeout, https_port,
                                          alt_hosts)
        else:  # pragma: no cover - argparse required=True guards this
            raise pe.UsageError("unknown command: %r" % (args.command,))
    except pe.UsageError as exc:
        pe.eprint("error: %s" % exc)
        return finish(pe.EXIT_USAGE)
    except pe.ResourceLimitError as exc:
        summary["resource_limited"] = True
        pe.eprint("error: %s; run aborted, results are partial" % exc)
        return finish(pe.EXIT_RESOURCE)
    except _WalkDone:
        return finish(pe.EXIT_TIMEOUT)
    except Exception as exc:  # defensive: no partial-success confusion
        pe.eprint("error: run failed: %s" % exc)
        return finish(pe.EXIT_FAIL)
    if summary["timed_out"] or summary["interrupted"]:
        return finish(pe.EXIT_TIMEOUT)
    return finish(pe.EXIT_OK)


if __name__ == "__main__":
    sys.exit(main())
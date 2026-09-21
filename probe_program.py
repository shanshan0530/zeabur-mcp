"""Fixed stdlib network probe for Zeabur service-container execution.

This entire module is the -c program sent to executeCommand. It must stay
stdlib-only, write nothing to the filesystem, and read host/port/url only
from argv (never interpolating caller values into source).
"""

import errno
import socket
import ssl
import sys
import threading
import time
from ipaddress import ip_address, IPv6Address
from urllib.parse import urlsplit

PROBE_MARKER = "zeabur-mcp-fixed-network-probe-v1"

DNS_TIMEOUT_S = 5.0
TCP_TIMEOUT_S = 5.0
TLS_TIMEOUT_S = 5.0
HTTP_TIMEOUT_S = 8.0
TOTAL_TIMEOUT_S = 20.0
MAX_RESOLVED_IPS = 8
MAX_OUTPUT_CHARS = 4096
MAX_URL_CHARS = 2048
MAX_PATH_QUERY_CHARS = 512
MAX_HOST_CHARS = 253
MAX_HTTP_READ = 2048

STATUS_OK = "OK"
STATUS_FAILED = "FAILED"
STATUS_INVALID_TARGET = "INVALID_TARGET"
STATUS_DNS_ERROR = "DNS_ERROR"
STATUS_DNS_PRIVATE_TARGET = "DNS_PRIVATE_TARGET"
STATUS_TCP_TIMEOUT = "TCP_TIMEOUT"
STATUS_TCP_ERROR = "TCP_ERROR"
STATUS_TLS_TIMEOUT = "TLS_TIMEOUT"
STATUS_TLS_ERROR = "TLS_ERROR"
STATUS_HTTP_TIMEOUT = "HTTP_TIMEOUT"
STATUS_HTTP_ERROR = "HTTP_ERROR"
STATUS_IMPLEMENTATION_ERROR = "IMPLEMENTATION_ERROR"

STAGE_TARGET = "TARGET"
STAGE_DNS = "DNS"
STAGE_TCP = "TCP"
STAGE_TLS = "TLS"
STAGE_HTTP = "HTTP"
STAGE_IMPLEMENTATION = "IMPLEMENTATION"

_FORBIDDEN_HOSTS = frozenset(
    (
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "0.0.0.0",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "metadata.google.com",
        "metadata.azure.com",
        "metadata.internal",
        "instance-data",
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster.local",
    )
)

_FORBIDDEN_SUFFIXES = (
    ".localhost",
    ".localdomain",
    ".google.internal",
    ".svc.cluster.local",
    ".cluster.local",
)

_HOST_ILLEGAL = set("/\\'\";|$`&<>(){}")


def normalize_host(host):
    if host is None:
        return ""
    text = str(host).strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        text = text[1:-1]
    if text.endswith("."):
        text = text[:-1]
    return text


def _host_header_value(host, port):
    raw = str(host).strip()
    if raw.startswith("[") and raw.endswith("]"):
        name = raw
    elif ":" in raw:
        name = "[%s]" % raw
    else:
        name = raw
    if int(port) == 443:
        return name
    return "%s:%s" % (name, port)


def ip_is_forbidden(value):
    try:
        ip = ip_address(str(value).split("%", 1)[0])
    except (TypeError, ValueError):
        return True
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def host_is_forbidden_name(host):
    name = normalize_host(host).lower()
    if not name:
        return True
    if name in _FORBIDDEN_HOSTS:
        return True
    if name.startswith("metadata."):
        return True
    for suffix in _FORBIDDEN_SUFFIXES:
        if name.endswith(suffix):
            return True
    return False


def host_has_illegal_chars(host):
    text = str(host).strip()
    inner = text[1:-1] if text.startswith("[") and text.endswith("]") and len(text) > 2 else text
    for ch in inner:
        if ch.isspace() or ord(ch) < 32 or ch in _HOST_ILLEGAL:
            return True
    return False


def host_is_ip_literal(host):
    try:
        ip_address(normalize_host(host).split("%", 1)[0])
        return True
    except (TypeError, ValueError):
        return False


def validate_https_url(url, target_host, target_port):
    if url is None:
        return None
    if not isinstance(url, str) or not url.strip():
        return "https_url is empty"
    text = url.strip()
    if len(text) > MAX_URL_CHARS:
        return "url too long"
    parts = urlsplit(text)
    if parts.scheme.lower() != "https":
        return "https only"
    if parts.username is not None or parts.password is not None:
        return "userinfo not allowed"
    if not parts.hostname:
        return "missing host"
    if normalize_host(parts.hostname).lower() != normalize_host(target_host).lower():
        return "https_url host mismatch"
    if parts.port is not None and int(parts.port) != int(target_port):
        return "https_url port mismatch"
    path = parts.path or ""
    query = ("?" + parts.query) if parts.query else ""
    if len(path + query) > MAX_PATH_QUERY_CHARS:
        return "path/query too long"
    return None


def validate_target(host, port, url=None):
    if not isinstance(host, str) or not host.strip():
        return "missing host"
    if host_has_illegal_chars(host):
        return "illegal host characters"
    name = normalize_host(host)
    if not name or len(name) > MAX_HOST_CHARS:
        return "invalid host"
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return "invalid port"
    if port_i < 1 or port_i > 65535:
        return "invalid port"
    if host_is_forbidden_name(name):
        return "forbidden hostname"
    if host_is_ip_literal(name) and ip_is_forbidden(name):
        return "forbidden address"
    if url:
        url_err = validate_https_url(url, name, port_i)
        if url_err:
            return url_err
    return None


def _is_timeout(exc):
    if isinstance(exc, socket.timeout):
        return True
    if isinstance(exc, TimeoutError):
        return True
    err = getattr(exc, "errno", None)
    if err in (errno.ETIMEDOUT, getattr(errno, "ETIME", None)):
        return True
    text = str(exc).lower()
    return "timed out" in text or "timeout" in text


def _ms(started):
    return (time.perf_counter() - started) * 1000.0


def _fmt_ms(value):
    if value is None:
        return None
    return "%.1f" % value


def _render(fields):
    lines = []
    for key, value in fields:
        if value is None:
            continue
        lines.append("%s=%s" % (key, value))
    text = "\n".join(lines)
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS]
    if not text.endswith("\n"):
        text += "\n"
    return text


def _fail(error_class, failed_stage, fields, extra=None):
    rows = [
        ("status", STATUS_FAILED if error_class not in (
            STATUS_INVALID_TARGET,
            STATUS_IMPLEMENTATION_ERROR,
        ) else error_class),
        ("failed_stage", failed_stage),
        ("error_class", error_class),
    ]
    rows.extend(fields)
    if extra:
        rows.extend(extra)
    status_for_ok = error_class if error_class in (
        STATUS_INVALID_TARGET,
        STATUS_IMPLEMENTATION_ERROR,
    ) else STATUS_FAILED
    # Keep INVALID_TARGET / IMPLEMENTATION_ERROR as the status line.
    rows[0] = ("status", status_for_ok)
    return error_class, _render(rows)


def _ok(fields):
    rows = [("status", STATUS_OK)]
    rows.extend(fields)
    return STATUS_OK, _render(rows)


def _resolve(host, port, timeout):
    box = {"addrs": None, "err": None}

    def worker():
        try:
            box["addrs"] = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)
        except Exception as exc:
            box["err"] = exc

    thread = threading.Thread(target=worker)
    thread.daemon = True
    started = time.perf_counter()
    thread.start()
    thread.join(timeout)
    elapsed = _ms(started)
    if thread.is_alive():
        return elapsed, None, "timeout"
    if box["err"] is not None:
        return elapsed, None, box["err"]
    return elapsed, box["addrs"] or [], None


def _extract_ips(addrinfo_list):
    ips = []
    seen = set()
    for item in addrinfo_list:
        sockaddr = item[4]
        if not sockaddr:
            continue
        ip = str(sockaddr[0]).split("%", 1)[0]
        if ip in seen:
            continue
        seen.add(ip)
        ips.append(ip)
        if len(ips) >= MAX_RESOLVED_IPS:
            break
    return ips


def _remaining(deadline, stage_timeout):
    left = deadline - time.monotonic()
    if left <= 0:
        return 0.0
    return min(float(stage_timeout), left)


def _http_target(url):
    parts = urlsplit(url.strip())
    path = parts.path or "/"
    if parts.query:
        path = "%s?%s" % (path, parts.query)
    return path


def run_probe(host, port, url=None):
    fields = []
    started_total = time.perf_counter()
    deadline = time.monotonic() + TOTAL_TIMEOUT_S
    sock = None
    wrapped = None

    def with_total(rows):
        out = list(rows)
        out.append(("total_ms", _fmt_ms(_ms(started_total))))
        return out

    try:
        reason = validate_target(host, port, url)
        if reason:
            cls, text = _fail(
                STATUS_INVALID_TARGET,
                STAGE_TARGET,
                with_total([("reason", reason)]),
            )
            return cls, text

        name = normalize_host(host)
        port_i = int(port)
        url_text = url.strip() if isinstance(url, str) and url.strip() else None

        dns_timeout = _remaining(deadline, DNS_TIMEOUT_S)
        if dns_timeout <= 0:
            cls, text = _fail(STATUS_DNS_ERROR, STAGE_DNS, with_total([("reason", "total timeout")]))
            return cls, text
        dns_ms, addrinfo, dns_err = _resolve(name, port_i, dns_timeout)
        fields.append(("dns_ms", _fmt_ms(dns_ms)))
        if dns_err is not None:
            error_class = STATUS_DNS_ERROR
            cls, text = _fail(
                error_class,
                STAGE_DNS,
                with_total(fields + [("reason", "timeout" if dns_err == "timeout" or _is_timeout(dns_err) else type(dns_err).__name__)]),
            )
            return cls, text

        ips = _extract_ips(addrinfo)
        fields.append(("resolved_ips", ",".join(ips) if ips else ""))
        if not ips:
            cls, text = _fail(STATUS_DNS_ERROR, STAGE_DNS, with_total(fields + [("reason", "empty resolution")]))
            return cls, text
        private_hits = [ip for ip in ips if ip_is_forbidden(ip)]
        if private_hits:
            cls, text = _fail(
                STATUS_DNS_PRIVATE_TARGET,
                STAGE_DNS,
                with_total(fields + [("reason", "resolved private or forbidden address")]),
            )
            return cls, text

        dest_ip = ips[0]
        tcp_timeout = _remaining(deadline, TCP_TIMEOUT_S)
        if tcp_timeout <= 0:
            cls, text = _fail(STATUS_TCP_TIMEOUT, STAGE_TCP, with_total(fields))
            return cls, text
        tcp_started = time.perf_counter()
        try:
            sock = socket.create_connection((dest_ip, port_i), timeout=tcp_timeout)
        except Exception as exc:
            fields.append(("tcp_ms", _fmt_ms(_ms(tcp_started))))
            error_class = STATUS_TCP_TIMEOUT if _is_timeout(exc) else STATUS_TCP_ERROR
            cls, text = _fail(
                error_class,
                STAGE_TCP,
                with_total(fields + [("reason", type(exc).__name__)]),
            )
            return cls, text
        fields.append(("tcp_ms", _fmt_ms(_ms(tcp_started))))

        tls_timeout = _remaining(deadline, TLS_TIMEOUT_S)
        if tls_timeout <= 0:
            cls, text = _fail(STATUS_TLS_TIMEOUT, STAGE_TLS, with_total(fields))
            return cls, text
        try:
            sock.settimeout(tls_timeout)
            tls_ctx = ssl.create_default_context()
            tls_started = time.perf_counter()
            wrapped = tls_ctx.wrap_socket(sock, server_hostname=name)
            sock = None
        except Exception as exc:
            fields.append(("tls_ms", _fmt_ms(_ms(tls_started) if "tls_started" in locals() else 0.0)))
            error_class = STATUS_TLS_TIMEOUT if _is_timeout(exc) else STATUS_TLS_ERROR
            cls, text = _fail(
                error_class,
                STAGE_TLS,
                with_total(fields + [("reason", type(exc).__name__)]),
            )
            return cls, text
        fields.append(("tls_ms", _fmt_ms(_ms(tls_started))))

        if url_text:
            http_timeout = _remaining(deadline, HTTP_TIMEOUT_S)
            if http_timeout <= 0:
                cls, text = _fail(STATUS_HTTP_TIMEOUT, STAGE_HTTP, with_total(fields))
                return cls, text
            path = _http_target(url_text)
            request = (
                "HEAD %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Connection: close\r\n"
                "User-Agent: zeabur-mcp-network-probe\r\n"
                "\r\n"
            ) % (path, _host_header_value(name, port_i))
            http_started = time.perf_counter()
            try:
                wrapped.settimeout(http_timeout)
                wrapped.sendall(request.encode("ascii"))
                chunk = wrapped.recv(MAX_HTTP_READ)
                http_ms = _ms(http_started)
                fields.append(("http_ttfb_ms", _fmt_ms(http_ms)))
                if not chunk:
                    cls, text = _fail(
                        STATUS_HTTP_ERROR,
                        STAGE_HTTP,
                        with_total(fields + [("reason", "empty response")]),
                    )
                    return cls, text
                try:
                    header = chunk.decode("iso-8859-1", "replace").split("\r\n", 1)[0]
                    parts = header.split()
                    http_status = parts[1] if len(parts) >= 2 else "unknown"
                except Exception:
                    http_status = "unknown"
                fields.append(("http_status", http_status))
            except Exception as exc:
                fields.append(("http_ttfb_ms", _fmt_ms(_ms(http_started))))
                error_class = STATUS_HTTP_TIMEOUT if _is_timeout(exc) else STATUS_HTTP_ERROR
                cls, text = _fail(
                    error_class,
                    STAGE_HTTP,
                    with_total(fields + [("reason", type(exc).__name__)]),
                )
                return cls, text

        cls, text = _ok(with_total(fields))
        return cls, text
    except Exception as exc:
        cls, text = _fail(
            STATUS_IMPLEMENTATION_ERROR,
            STAGE_IMPLEMENTATION,
            with_total(fields + [("reason", type(exc).__name__)]),
        )
        return cls, text
    finally:
        for item in (wrapped, sock):
            if item is None:
                continue
            try:
                item.close()
            except Exception:
                pass


def main(argv=None):
    args = list(sys.argv if argv is None else argv)
    if len(args) < 4:
        cls, text = _fail(
            STATUS_IMPLEMENTATION_ERROR,
            STAGE_IMPLEMENTATION,
            [("reason", "missing argv host/port/url")],
        )
        sys.stdout.write(text)
        return 2
    host = args[1]
    port_raw = args[2]
    url = args[3] if args[3] else None
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        cls, text = _fail(
            STATUS_INVALID_TARGET,
            STAGE_TARGET,
            [("reason", "invalid port")],
        )
        sys.stdout.write(text)
        return 2
    cls, text = run_probe(host, port, url)
    sys.stdout.write(text)
    if cls == STATUS_OK:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

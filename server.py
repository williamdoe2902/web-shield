import ipaddress
import json
import re
import threading
import time
import uuid
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


HOST = "127.0.0.1"
PORT = 8000
MAX_PAGES = 40
MAX_DEPTH = 3
MAX_HISTORY = 20
MAX_BODY_BYTES = 1_000_000
TIMEOUT_SECONDS = 4
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
SCANS = {}
SCAN_LOCK = threading.Lock()


def is_loopback_url(url):
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        if parts.username is not None or parts.password is not None:
            return False
        hostname = parts.hostname.lower()
        if hostname == "localhost":
            return True
        return ipaddress.ip_address(hostname).is_loopback
    except (ValueError, TypeError):
        return False


def normalized_url(url):
    parts = urlsplit(url)
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def same_origin(left, right):
    a = urlsplit(left)
    b = urlsplit(right)
    try:
        a_port = a.port or (443 if a.scheme == "https" else 80)
        b_port = b.port or (443 if b.scheme == "https" else 80)
        return (
            a.scheme.lower() == b.scheme.lower()
            and a.hostname.lower() == b.hostname.lower()
            and a_port == b_port
        )
    except (AttributeError, ValueError):
        return False


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag.lower() == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").lower(),
                "fields": [],
            }
        elif tag.lower() in ("input", "textarea", "select") and self.current_form is not None:
            field_type = attrs.get("type", "text").lower()
            name = attrs.get("name", "")
            if name:
                self.current_form["fields"].append({
                    "name": name[:100],
                    "type": field_type[:30],
                })

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_fetch(url):
    if not is_loopback_url(url):
        raise ValueError("Only localhost and loopback IP targets are allowed.")

    opener = build_opener(NoRedirectHandler())
    current = url
    for _ in range(4):
        request = Request(
            current,
            headers={"User-Agent": "WebShield-Local-Audit/1.0", "Accept": "text/html,*/*;q=0.5"},
            method="GET",
        )
        try:
            response = opener.open(request, timeout=TIMEOUT_SECONDS)
        except HTTPError as error:
            if error.code in (301, 302, 303, 307, 308):
                location = error.headers.get("Location")
                next_url = urljoin(current, location or "")
                if not location or not is_loopback_url(next_url) or not same_origin(url, next_url):
                    raise ValueError("Redirect blocked: it leaves the original local origin.")
                current = next_url
                continue
            return error.code, error.headers, error.read(MAX_BODY_BYTES), current
        with response:
            return response.status, response.headers, response.read(MAX_BODY_BYTES), current
    raise ValueError("Too many redirects.")


def add_finding(findings, title, severity, url, evidence, recommendation):
    key = (title, url)
    if any((item["title"], item["url"]) == key for item in findings):
        return
    findings.append({
        "id": str(uuid.uuid4()),
        "title": title,
        "severity": severity,
        "url": url,
        "evidence": evidence,
        "recommendation": recommendation,
    })


def scan_target(scan_id, start_url):
    pages = []
    forms = []
    findings = []
    queue = [(normalized_url(start_url), 0)]
    visited = set()
    root_origin = start_url
    error_message = None

    while queue and len(visited) < MAX_PAGES:
        url, depth = queue.pop(0)
        if url in visited or depth > MAX_DEPTH:
            continue
        visited.add(url)
        try:
            status, headers, body, final_url = safe_fetch(url)
        except (ValueError, URLError, TimeoutError, OSError) as error:
            error_message = str(error)
            continue

        page_url = normalized_url(final_url)
        content_type = headers.get("Content-Type", "")
        page_record = {"url": page_url, "status": status, "contentType": content_type}
        pages.append(page_record)

        if depth == 0:
            checks = [
                ("Content-Security-Policy", "Medium", "Add a restrictive Content-Security-Policy, starting in report-only mode if needed."),
                ("X-Content-Type-Options", "Low", "Set X-Content-Type-Options: nosniff."),
                ("Referrer-Policy", "Low", "Set a Referrer-Policy appropriate to the application, such as strict-origin-when-cross-origin."),
            ]
            for name, severity, recommendation in checks:
                if not headers.get(name):
                    add_finding(
                        findings, f"Missing {name}", severity, page_url,
                        f"The response did not include the {name} header.", recommendation,
                    )
            if page_url.startswith("https://") and not headers.get("Strict-Transport-Security"):
                add_finding(
                    findings, "Missing Strict-Transport-Security", "Low", page_url,
                    "The HTTPS response did not include the HSTS header.",
                    "Set Strict-Transport-Security with an appropriate max-age after confirming HTTPS works across the site.",
                )
            if not headers.get("X-Frame-Options") and "frame-ancestors" not in headers.get("Content-Security-Policy", "").lower():
                add_finding(
                    findings, "No clickjacking protection detected", "Low", page_url,
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive was detected.",
                    "Set a CSP frame-ancestors directive or X-Frame-Options where framing is not required.",
                )
            for header_name in ("Server", "X-Powered-By"):
                value = headers.get(header_name)
                if value:
                    add_finding(
                        findings, f"Technology banner exposed ({header_name})", "Info", page_url,
                        f"The response reveals: {header_name}: {value[:160]}",
                        "Consider minimizing version and platform details in response headers.",
                    )

        text = body.decode("utf-8", errors="replace")
        db_errors = (
            r"SQL syntax.*MySQL", r"Warning:\s*mysql_", r"ORA-\d{5}",
            r"PostgreSQL.*ERROR", r"Microsoft OLE DB Provider for SQL Server",
            r"SQLite/JDBCDriver",
        )
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in db_errors):
            add_finding(
                findings, "Possible database error disclosure", "Medium", page_url,
                "A database-related error signature was present in the returned page; no injection test was sent.",
                "Show generic errors to users and log database diagnostics only in protected server-side logs.",
            )

        if "html" in content_type.lower() or not content_type:
            parser = PageParser()
            parser.feed(text)
            for form in parser.forms:
                action = normalized_url(urljoin(page_url, form["action"] or page_url))
                form_record = {
                    "page": page_url,
                    "action": action,
                    "method": form["method"],
                    "fields": form["fields"],
                }
                forms.append(form_record)
                has_password = any(field["type"] == "password" for field in form["fields"])
                if has_password and form["method"] == "get":
                    add_finding(
                        findings, "Password form uses GET", "High", page_url,
                        f"A password field is present in a GET form targeting {action}.",
                        "Submit credentials using POST over HTTPS; ensure secrets never appear in URLs, browser history, or access logs.",
                    )
                if has_password and page_url.startswith("http://"):
                    add_finding(
                        findings, "Password form served over HTTP", "High", page_url,
                        "A password field was found on a page loaded without TLS.",
                        "Serve the login page and its submission endpoint exclusively over HTTPS.",
                    )
                if form["method"] == "post" and not any(
                    re.search(r"csrf|xsrf|authenticity|request.?token", field["name"], re.IGNORECASE)
                    for field in form["fields"]
                ):
                    add_finding(
                        findings, "Review POST form CSRF protections", "Info", page_url,
                        f"No commonly named CSRF token field was detected in the form targeting {action}; this heuristic cannot confirm whether CSRF protection exists.",
                        "Verify server-side CSRF defenses, including token validation and appropriate SameSite cookie settings.",
                    )
            if depth < MAX_DEPTH:
                for href in parser.links:
                    candidate = urljoin(page_url, href)
                    if is_loopback_url(candidate) and same_origin(root_origin, candidate):
                        candidate = normalized_url(candidate)
                        if candidate not in visited and all(candidate != item[0] for item in queue):
                            queue.append((candidate, depth + 1))

        with SCAN_LOCK:
            scan = SCANS.get(scan_id)
            if scan:
                scan["progress"] = min(95, int(len(visited) / MAX_PAGES * 100))
                scan["pagesScanned"] = len(pages)
                scan["findings"] = findings[:]
                scan["pages"] = pages[:]
                scan["forms"] = forms[:]

    with SCAN_LOCK:
        scan = SCANS.get(scan_id)
        if scan:
            scan.update({
                "status": "completed",
                "progress": 100,
                "pagesScanned": len(pages),
                "pages": pages,
                "forms": forms,
                "findings": findings,
                "error": error_message,
                "completedAt": time.time(),
            })


class WebShieldHandler(BaseHTTPRequestHandler):
    server_version = "WebShield/1.0"

    def log_message(self, fmt, *args):
        return

    def send_json(self, status, value):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/scans":
            with SCAN_LOCK:
                history = [
                    {
                        "id": scan["id"],
                        "target": scan["target"],
                        "status": scan["status"],
                        "startedAt": scan["startedAt"],
                        "pagesScanned": scan["pagesScanned"],
                        "findingCount": len(scan["findings"]),
                    }
                    for scan in sorted(SCANS.values(), key=lambda item: item["startedAt"], reverse=True)
                ]
            self.send_json(200, history)
            return
        if path.startswith("/api/scans/"):
            scan_id = path.rsplit("/", 1)[-1]
            with SCAN_LOCK:
                scan = SCANS.get(scan_id)
                if scan:
                    self.send_json(200, scan)
                else:
                    self.send_json(404, {"error": "Scan not found."})
            return
        if path in STATIC_FILES:
            filename, content_type = STATIC_FILES[path]
            try:
                with open(filename, "rb") as file:
                    body = file.read()
            except OSError:
                self.send_error(500, "Application files could not be read.")
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        if self.path != "/api/scans":
            self.send_json(404, {"error": "Endpoint not found."})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 4096:
                raise ValueError("Request body must be between 1 and 4096 bytes.")
            payload = json.loads(self.rfile.read(size))
            target = payload.get("target", "").strip()
            parts = urlsplit(target)
            if not is_loopback_url(target) or not parts.netloc:
                raise ValueError("Target must be an HTTP(S) URL on localhost or a loopback IP address.")
        except (ValueError, json.JSONDecodeError, AttributeError) as error:
            self.send_json(400, {"error": str(error)})
            return

        scan_id = str(uuid.uuid4())
        scan = {
            "id": scan_id,
            "target": normalized_url(target),
            "status": "running",
            "progress": 0,
            "pagesScanned": 0,
            "pages": [],
            "forms": [],
            "findings": [],
            "startedAt": time.time(),
            "error": None,
        }
        with SCAN_LOCK:
            completed = sorted(
                (item for item in SCANS.values() if item["status"] == "completed"),
                key=lambda item: item["startedAt"],
            )
            while len(completed) >= MAX_HISTORY:
                del SCANS[completed.pop(0)["id"]]
            SCANS[scan_id] = scan
        threading.Thread(target=scan_target, args=(scan_id, target), daemon=True).start()
        self.send_json(202, {"id": scan_id})


if __name__ == "__main__":
    print(f"WebShield is running at http://{HOST}:{PORT} (local targets only)")
    ThreadingHTTPServer((HOST, PORT), WebShieldHandler).serve_forever()

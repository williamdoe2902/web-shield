# WebShield — Local Web Security Scanner

WebShield is a small Python and browser-based project for mapping and reviewing a web application running on the same machine.

## Run it

1. Install Python 3.10 or newer.
2. From this folder, run `python server.py`.
3. Open `http://127.0.0.1:8000`.
4. Start a local training target separately (for example, an OWASP Juice Shop or DVWA instance you are authorized to test) and enter its local URL.

The scanner accepts only `localhost`, `127.0.0.1`, and loopback IP addresses. It follows same-origin links only, limits a scan to 40 pages and depth 3, uses GET requests, and does not submit forms, execute scripts, or send exploit payloads. It reports response-header issues, exposed database error signatures in ordinary responses, and a few passive form-security indicators. These are observations, not proof of SQL injection, XSS, or other exploitability.

The interface exports a downloadable HTML report. Scan state is held in memory while the server runs; no scan data is sent to a remote service or persisted between server restarts.

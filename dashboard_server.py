
"""
Nanobricks Endpoint360
Local Dashboard Server v0.1.0

Serves the HTML dashboard and the latest combined assessment report.
Read-only. Uses Python standard library only.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DASHBOARD = ROOT / "dashboard"
REPORTS = ROOT / "reports"

HOST = "127.0.0.1"
PORT = 8765

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


class DashboardHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/api/latest-report":
            self.serve_latest_report()
            return

        if path == "/":
            path = "/index.html"

        relative_path = path.lstrip("/")
        requested_file = (DASHBOARD / relative_path).resolve()

        if not requested_file.is_relative_to(DASHBOARD.resolve()):
            self.send_error(403, "Access denied")
            return

        if not requested_file.is_file():
            self.send_error(404, "File not found")
            return

        content_type = CONTENT_TYPES.get(requested_file.suffix.lower())

        if content_type is None:
            self.send_error(403, "Unsupported file type")
            return

        content = requested_file.read_bytes()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def serve_latest_report(self):
        reports = sorted(
            REPORTS.glob("*-Endpoint360-*.json"),
            key=lambda file: file.stat().st_mtime,
            reverse=True,
        )

        if not reports:
            self.send_json(
                {"error": "No Endpoint360 assessment reports found"},
                404,
            )
            return

        try:
            with reports[0].open("r", encoding="utf-8") as file:
                report = json.load(file)
        except (OSError, UnicodeError, json.JSONDecodeError):
            self.send_json(
                {"error": "Latest assessment report could not be read"},
                500,
            )
            return

        self.send_json(report)

    def send_json(self, data, status=200):
        content = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)

    print("=" * 55)
    print(" NANOBRICKS ENDPOINT360")
    print(" Local Dashboard Server v0.1.0")
    print("=" * 55)
    print(f"Dashboard: http://{HOST}:{PORT}")
    print(f"Report API: http://{HOST}:{PORT}/api/latest-report")
    print("Mode: READ ONLY")
    print("Press Ctrl+C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard server stopped.")
    finally:
        server.server_close()


"""
Nanobricks Endpoint360
Local Dashboard Server v0.2.0

Serves:
- Endpoint360 HTML dashboard
- Latest combined assessment report
- Latest Security Compliance report

Read-only.
Uses Python standard library only.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


VERSION = "0.2.0"

ROOT = Path(__file__).resolve().parent
DASHBOARD = ROOT / "dashboard"
REPORTS = ROOT / "reports"
COMPLIANCE_REPORTS = ROOT / "compliance" / "reports"

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

        # Existing Endpoint360 combined assessment API
        if path == "/api/latest-report":
            self.serve_latest_report()
            return

        # New Security Compliance API
        if path == "/api/latest-compliance":
            self.serve_latest_compliance()
            return

        # Existing dashboard file serving
        if path == "/":
            path = "/index.html"

        relative_path = path.lstrip("/")
        requested_file = (DASHBOARD / relative_path).resolve()

        # Prevent access outside the dashboard directory
        if not requested_file.is_relative_to(DASHBOARD.resolve()):
            self.send_error(403, "Access denied")
            return

        if not requested_file.is_file():
            self.send_error(404, "File not found")
            return

        content_type = CONTENT_TYPES.get(
            requested_file.suffix.lower()
        )

        if content_type is None:
            self.send_error(403, "Unsupported file type")
            return

        try:
            content = requested_file.read_bytes()
        except OSError:
            self.send_error(500, "Unable to read dashboard file")
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def serve_latest_report(self):
        """
        Return the newest combined Endpoint360 assessment.

        Existing endpoint:
        /api/latest-report
        """

        reports = sorted(
            REPORTS.glob("*-Endpoint360-*.json"),
            key=lambda file: file.stat().st_mtime,
            reverse=True,
        )

        if not reports:
            self.send_json(
                {
                    "error": (
                        "No Endpoint360 assessment reports found"
                    )
                },
                404,
            )
            return

        try:
            with reports[0].open(
                "r",
                encoding="utf-8",
            ) as file:
                report = json.load(file)

        except (OSError, UnicodeError, json.JSONDecodeError):
            self.send_json(
                {
                    "error": (
                        "Latest assessment report could not be read"
                    )
                },
                500,
            )
            return

        self.send_json(report)

    def serve_latest_compliance(self):
        """
        Return the newest Security Compliance assessment.

        New endpoint:
        /api/latest-compliance
        """

        reports = sorted(
            COMPLIANCE_REPORTS.glob("*-Compliance-*.json"),
            key=lambda file: file.stat().st_mtime,
            reverse=True,
        )

        if not reports:
            self.send_json(
                {
                    "error": (
                        "No compliance assessment reports found"
                    )
                },
                404,
            )
            return

        try:
            with reports[0].open(
                "r",
                encoding="utf-8",
            ) as file:
                report = json.load(file)

        except (OSError, UnicodeError, json.JSONDecodeError):
            self.send_json(
                {
                    "error": (
                        "Latest compliance report could not be read"
                    )
                },
                500,
            )
            return

        self.send_json(report)

    def send_json(self, data, status=200):
        """
        Return a JSON response without caching.
        """

        content = json.dumps(
            data,
            ensure_ascii=False,
        ).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(content)),
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        self.wfile.write(content)


if __name__ == "__main__":

    server = ThreadingHTTPServer(
        (HOST, PORT),
        DashboardHandler,
    )

    print("=" * 55)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Local Dashboard Server v{VERSION}")
    print("=" * 55)

    print()
    print(f"Dashboard: http://{HOST}:{PORT}")
    print(
        f"Assessment API: "
        f"http://{HOST}:{PORT}/api/latest-report"
    )
    print(
        f"Compliance API: "
        f"http://{HOST}:{PORT}/api/latest-compliance"
    )

    print()
    print("Mode: READ ONLY")
    print("Press Ctrl+C to stop.")
    print()

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nDashboard server stopped.")

    finally:
        server.server_close()

"""
Web Server & REST API for Phase-II Demonstration:
"Beyond Metadata Filtering: An Authorization-Integrity Layer for Secure Multi-Tenant Industrial RAG Systems"
Runs with zero external dependencies using Python's standard library ThreadingHTTPServer.
"""

import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from rag_engine import IndustrialRAGSystem

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

rag_system = IndustrialRAGSystem()


class RAGIntegrityRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        # Clean console logs
        sys.stdout.write(f"[API] {self.address_string()} - {format % args}\n")

    def _send_json(self, payload: dict, status: int = 200) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        body = self.rfile.read(length).decode("utf-8")
        return json.loads(body) if body else {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/state":
            self._send_json(rag_system.get_full_state())
            return

        if path == "/api/evaluate":
            report = rag_system.run_evaluation_benchmark(iterations=5)
            self._send_json({"report": report, "state": rag_system.get_full_state()})
            return

        # Serve static files
        if path == "/" or path == "":
            file_path = os.path.join(STATIC_DIR, "index.html")
        else:
            rel_path = path.lstrip("/").replace("/", os.sep)
            file_path = os.path.join(STATIC_DIR, rel_path)

        if os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            mime_type = mime_type or "application/octet-stream"
            with open(file_path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        else:
            self._send_json({"error": f"Not found: {path}"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()

            if path == "/api/query":
                tenant = body.get("tenant", "Factory B")
                query_text = body.get("query", "").strip()
                if not query_text:
                    self._send_json({"error": "Query cannot be empty"}, status=400)
                    return
                result = rag_system.run_query_comparison(
                    requesting_tenant=tenant,
                    query_text=query_text,
                    top_k=int(body.get("top_k", 4)),
                    log_decisions=True,
                )
                self._send_json({"result": result, "state": rag_system.get_full_state()})
                return

            if path == "/api/fault":
                fault_id = body.get("fault_id", "")
                enable = body.get("enable", None)
                fault_info = rag_system.toggle_fault(fault_id, enable)
                self._send_json({"fault": fault_info, "state": rag_system.get_full_state()})
                return

            if path == "/api/ingest":
                doc_id = body.get("doc_id", f"DOC-CUSTOM-{len(rag_system.policy_registry) + 1}")
                title = body.get("title", "Untitled Industrial Specification")
                doc_type = body.get("doc_type", "Maintenance Manual")
                claimed_tenant = body.get("claimed_tenant_tag", "Factory B")
                authoritative_owner = body.get("authoritative_owner", "Factory A")
                content = body.get("content", "")
                res = rag_system.ingest_document_with_validation(
                    doc_id=doc_id,
                    title=title,
                    doc_type=doc_type,
                    claimed_tenant_tag=claimed_tenant,
                    authoritative_owner=authoritative_owner,
                    content=content,
                )
                self._send_json({"ingestion": res, "state": rag_system.get_full_state()})
                return

            if path == "/api/evaluate":
                iterations = int(body.get("iterations", 5))
                report = rag_system.run_evaluation_benchmark(iterations=iterations)
                self._send_json({"report": report, "state": rag_system.get_full_state()})
                return

            if path == "/api/reset":
                rag_system.reset()
                self._send_json({"state": rag_system.get_full_state()})
                return

            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

        except Exception as exc:
            self._send_json({"error": str(exc)}, status=500)


def main() -> None:
    port = int(os.environ.get("PORT", "8050"))
    server = ThreadingHTTPServer(("127.0.0.1", port), RAGIntegrityRequestHandler)
    print("=" * 78)
    print("  Beyond Metadata Filtering: Authorization-Integrity Layer for Industrial RAG")
    print("  EL Phase-II Live Demonstration Server")
    print(f"  Dashboard URL: http://localhost:{port}")
    print("=" * 78)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.server_close()


if __name__ == "__main__":
    main()

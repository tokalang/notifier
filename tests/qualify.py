#!/usr/bin/env python3
"""Comprehensive RC6 Standalone Qualification Test Suite for tokalang/notifier v0.1.2."""

from __future__ import annotations

import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import platform
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def log(msg: str) -> None:
    print(f"[QUALIFY] {msg}", flush=True)


def find_sdk() -> tuple[Path, Path, Path]:
    sdk_env = os.environ.get("TOKA_SDK", "/tmp/toka-sdk-rc6")
    root_path = Path(sdk_env)
    toka = root_path / "bin" / "toka"
    tokac = root_path / "bin" / "tokac"
    lib = root_path / "lib"
    if not toka.is_file() or not tokac.is_file() or not lib.is_dir():
        toka_w = shutil.which("toka")
        tokac_w = shutil.which("tokac")
        toka_lib = os.environ.get("TOKA_LIB")
        if toka_w and tokac_w:
            toka = Path(toka_w)
            tokac = Path(tokac_w)
            lib = Path(toka_lib) if toka_lib else toka.parent.parent / "lib"
            if lib.is_dir():
                return toka, tokac, lib
        raise RuntimeError(f"Invalid TOKA_SDK at {sdk_env}: missing bin/toka, bin/tokac, or lib/")
    return toka, tokac, lib


def run_cmd(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    res = subprocess.run(cmd, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed (exit {res.returncode}): {' '.join(cmd)}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
    return res


def compile_notifier(repo_root: Path, tokac: Path, sdk_lib: Path) -> Path:
    target_dir = repo_root / "target"
    target_dir.mkdir(parents=True, exist_ok=True)

    main_ll = target_dir / "main.ll"
    run_cmd([
        str(tokac),
        "-I", str(sdk_lib),
        "-I", str(repo_root),
        "--emit-llvm",
        str(repo_root / "src" / "main.tk"),
        "-o", str(main_ll)
    ], cwd=repo_root)

    notifier_bin = target_dir / "notifier"
    rt_obj = sdk_lib / "sys" / "toka_rt.o"
    
    link_cmd = ["clang", str(main_ll), str(rt_obj)]
    try:
        pkg = subprocess.run(["pkg-config", "--libs", "openssl"], stdout=subprocess.PIPE, text=True)
        if pkg.returncode == 0 and pkg.stdout.strip():
            link_cmd.extend(pkg.stdout.strip().split())
        else:
            link_cmd.extend(["-lssl", "-lcrypto"])
    except Exception:
        link_cmd.extend(["-lssl", "-lcrypto"])

    link_cmd.extend(["-lm", "-lpthread", "-ldl"])

    if platform.system() == "Darwin":
        sdk_path = subprocess.run(["xcrun", "--show-sdk-path"], stdout=subprocess.PIPE, text=True).stdout.strip()
        if sdk_path:
            link_cmd.extend(["-isysroot", sdk_path])

    link_cmd.extend(["-o", str(notifier_bin)])
    run_cmd(link_cmd, cwd=repo_root)
    assert notifier_bin.is_file() and os.access(notifier_bin, os.X_OK)
    return notifier_bin


def generate_cert(cert_path: Path, key_path: Path, san_list: list[str], common_name: str = "localhost") -> None:
    san_entries = "\n".join([f"{entry}" for entry in san_list])
    san_conf = f"""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = {common_name}
[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
{san_entries}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as f:
        f.write(san_conf)
        cnf_path = f.name
    try:
        run_cmd([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-days", "1",
            "-config", cnf_path
        ])
    finally:
        os.unlink(cnf_path)


class MockServerHandler(BaseHTTPRequestHandler):
    recorded_requests: list[dict] = []
    response_sequence: list[tuple[int, bytes, dict, bool | list[int]]] = [] # (status, raw_body_bytes, headers, is_chunked or chunk_sizes)
    lock = threading.Lock()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        
        with self.lock:
            self.recorded_requests.append({
                "path": self.path,
                "headers": dict(self.headers),
                "body": body
            })
            if self.response_sequence:
                status, resp_bytes, headers, chunking_spec = self.response_sequence.pop(0)
            else:
                status, resp_bytes, headers, chunking_spec = 200, b'{"status":"ok"}', {}, False

        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        if "Content-Type" not in headers:
            self.send_header("Content-Type", "application/json")

        try:
            if chunking_spec is True or isinstance(chunking_spec, list):
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                if isinstance(chunking_spec, list):
                    # Custom chunk slices
                    idx = 0
                    for sz in chunking_spec:
                        chunk = resp_bytes[idx:idx + sz]
                        if chunk:
                            self.wfile.write(f"{len(chunk):x}\r\n".encode("utf-8"))
                            self.wfile.write(chunk)
                            self.wfile.write(b"\r\n")
                        idx += sz
                    if idx < len(resp_bytes):
                        rem_chunk = resp_bytes[idx:]
                        self.wfile.write(f"{len(rem_chunk):x}\r\n".encode("utf-8"))
                        self.wfile.write(rem_chunk)
                        self.wfile.write(b"\r\n")
                else:
                    chunk_size = 8192
                    for i in range(0, len(resp_bytes), chunk_size):
                        chunk = resp_bytes[i:i + chunk_size]
                        self.wfile.write(f"{len(chunk):x}\r\n".encode("utf-8"))
                        self.wfile.write(chunk)
                        self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format, *args):
        pass


def run_http_server(handler_cls, is_ssl: bool = False, cert_path: Path | None = None, key_path: Path | None = None) -> tuple[HTTPServer, int, threading.Thread]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_port
    if is_ssl and cert_path and key_path:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port, t


def main() -> int:
    log("=== Stage 1: Toolchain and Compiler Verification ===")
    repo_root = Path(__file__).resolve().parent.parent
    toka, tokac, sdk_lib = find_sdk()
    log(f"Found Toka SDK: toka={toka}, tokac={tokac}, lib={sdk_lib}")

    res = run_cmd([str(toka), "--version"])
    assert "1.0.0-rc.6" in res.stdout
    res = run_cmd([str(tokac), "--version"])
    assert "1.0.0-rc.6" in res.stdout
    log("Toolchain baseline 1.0.0-rc.6 verified.")

    log("=== Stage 2: Compile notifier application ===")
    notifier_bin = compile_notifier(repo_root, tokac, sdk_lib)
    log(f"Successfully compiled notifier executable: {notifier_bin}")

    work_dir = Path(tempfile.mkdtemp(prefix="notifier_qualify_"))
    try:
        log("=== Stage 3: Baseline CLI Tests (--help, --version) ===")
        res = run_cmd([str(notifier_bin), "--help"])
        assert "notifier - Controlled outbound HTTP/TLS delivery" in res.stdout
        assert "--dry-run" in res.stdout

        res = run_cmd([str(notifier_bin), "--version"])
        assert "notifier 0.1.2" in res.stdout

        log("=== Stage 4: YAML with Hash Inside Quoted String & Dry-Run Redaction ===")
        sample_event = work_dir / "event1.json"
        raw_event_text = '{\n  "event": "deployment_succeeded",\n  "version": "1.0.0",\n  "cluster": "prod-us-east-1"\n}\n'
        sample_event.write_text(raw_event_text, encoding="utf-8")
        expected_sha = hashlib.sha256(raw_event_text.encode("utf-8")).hexdigest()

        yaml_hash_cfg = work_dir / "config_hash.yaml"
        yaml_hash_cfg.write_text("""endpoint: "https://api.example.com/webhook"
timeout_ms: 3000
headers:
  Authorization: "Bearer secret#with#multiple#hashes#12345"
  X-Custom-Token: "value#hash"
  X-Service-Name: "billing-service"
""", encoding="utf-8")

        res = run_cmd([str(notifier_bin), "--config", str(yaml_hash_cfg), "--event", str(sample_event), "--dry-run", "send"])
        assert "=== NOTIFIER DRY RUN SIMULATION ===" in res.stdout
        assert f"Idempotency-Key: {expected_sha}" in res.stdout
        assert "authorization: [redacted]" in res.stdout.lower()
        assert "secret#with#multiple" not in res.stdout
        assert "x-service-name: billing-service" in res.stdout.lower()

        log("=== Stage 5: YAML Schema: Unknown Field Rejection ===")
        unknown_cfg = work_dir / "config_unknown.yaml"
        unknown_cfg.write_text("""endpoint: "https://api.example.com/webhook"
unknown_custom_field: "invalid"
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(unknown_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0
        assert "Unknown configuration field 'unknown_custom_field'" in res.stdout or "Unknown configuration field 'unknown_custom_field'" in res.stderr

        log("=== Stage 6: YAML Schema: Invalid Types and Out-of-Range Rejections ===")
        float_cfg = work_dir / "config_float.yaml"
        float_cfg.write_text("""endpoint: "https://api.example.com/webhook"
timeout_ms: 500.5
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(float_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0
        assert "must be an integer between 1 and 300000" in res.stdout or "must be an integer between 1 and 300000" in res.stderr

        neg_cfg = work_dir / "config_neg.yaml"
        neg_cfg.write_text("""endpoint: "https://api.example.com/webhook"
max_retries: -1
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(neg_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0

        array_cfg = work_dir / "config_array.yaml"
        array_cfg.write_text("""endpoint: "https://api.example.com/webhook"
headers:
  - "invalid-array"
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(array_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0

        log("=== Stage 7: Reserved System Header Configuration Error (Fail-Closed) ===")
        tamper_cfg = work_dir / "config_tamper.yaml"
        tamper_cfg.write_text("""endpoint: "https://api.example.com/v1"
headers:
  Host: "evil-spoofed.com"
  Content-Length: "0"
  Idempotency-Key: "tampered-key-0000"
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(tamper_cfg), "--event", str(sample_event), "--dry-run", "send"], check=False)
        assert res.returncode != 0
        assert "Forbidden attempt to set reserved system header" in res.stdout or "Forbidden attempt to set reserved system header" in res.stderr

        log("=== Stage 8: Scheme Whitelist Rejection (Non-HTTP/HTTPS) ===")
        wss_cfg = work_dir / "config_wss.yaml"
        wss_cfg.write_text("""endpoint: "wss://api.example.com/stream"
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(wss_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0
        assert "Unsupported URL scheme 'wss'" in res.stdout or "Unsupported URL scheme 'wss'" in res.stderr

        ftp_cfg = work_dir / "config_ftp.yaml"
        ftp_cfg.write_text("""endpoint: "ftp://localhost:21/file"
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(ftp_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0
        assert "Unsupported URL scheme 'ftp'" in res.stdout or "Unsupported URL scheme 'ftp'" in res.stderr

        log("=== Stage 9: Missing Authority Rejection ===")
        nohost_cfg = work_dir / "config_nohost.yaml"
        nohost_cfg.write_text("""endpoint: "http:///missing-host"
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(nohost_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0
        assert "Invalid endpoint URL" in res.stdout or "missing host/authority" in res.stdout or "Invalid endpoint URL" in res.stderr or "missing host/authority" in res.stderr

        log("=== Stage 10: Security Policy & Insecure Plain HTTP Rejection ===")
        insecure_cfg = work_dir / "config_insecure.yaml"
        insecure_cfg.write_text("""endpoint: "http://api.public-service.com/webhook"
timeout_ms: 2000
""", encoding="utf-8")

        res = run_cmd([str(notifier_bin), "--config", str(insecure_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0
        assert "forbidden by security policy" in res.stdout or "forbidden by security policy" in res.stderr

        res = run_cmd([str(notifier_bin), "--config", str(insecure_cfg), "--event", str(sample_event), "--allow-insecure-http", "--dry-run", "send"])
        assert "[WARNING: INSECURE OVERRIDE]" in res.stdout

        log("=== Stage 11: Host Match Strict Equality (Prefix Spoof Defense) ===")
        spoof_cfg = work_dir / "config_spoof.yaml"
        spoof_cfg.write_text("""endpoint: "http://localhost.attacker.com/webhook"
timeout_ms: 1000
""", encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(spoof_cfg), "--event", str(sample_event), "send"], check=False)
        assert res.returncode != 0
        assert "forbidden by security policy" in res.stdout or "forbidden by security policy" in res.stderr

        log("=== Stage 12: Malformed JSON Event Payload Rejection ===")
        bad_event = work_dir / "bad_event.json"
        bad_event.write_text('{ "unclosed": "brace"', encoding="utf-8")
        res = run_cmd([str(notifier_bin), "--config", str(yaml_hash_cfg), "--event", str(bad_event), "send"], check=False)
        assert res.returncode != 0
        assert "not valid JSON" in res.stdout or "not valid JSON" in res.stderr

        log("=== Stage 13: Local Loopback HTTP Delivery (200 OK) ===")
        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence.clear()
        http_server, http_port, _ = run_http_server(MockServerHandler)
        try:
            http_cfg = work_dir / "config_http.yaml"
            http_cfg.write_text(f"""endpoint: "http://127.0.0.1:{http_port}/api/events?source=ci"
timeout_ms: 3000
headers:
  X-Event-Topic: "deployments"
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(http_cfg), "--event", str(sample_event), "send"])
            assert res.returncode == 0
            assert "[SUCCESS]" in res.stdout
            assert f"Status: 200, Idempotency-Key: {expected_sha}" in res.stdout

            with MockServerHandler.lock:
                assert len(MockServerHandler.recorded_requests) == 1
                rec = MockServerHandler.recorded_requests[0]
                rec_headers_lower = {k.lower(): v for k, v in rec["headers"].items()}
                assert rec["path"] == "/api/events?source=ci"
                assert rec["body"] == raw_event_text
                assert rec_headers_lower.get("idempotency-key") == expected_sha
                assert rec_headers_lower.get("content-type") == "application/json"
                assert rec_headers_lower.get("x-event-topic") == "deployments"
                assert rec_headers_lower.get("user-agent") == "toka-notifier/0.1.2"
        finally:
            http_server.shutdown()

        log("=== Stage 14: 302 Redirect Immediate Rejection (Status-First, Large Body Unread) ===")
        large_redirect_body = b"X" * (5 * 1024 * 1024) # 5 MB redirect body
        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence = [(302, large_redirect_body, {"Location": "http://127.0.0.1:9999/other"}, False)]
        http_server, http_port, _ = run_http_server(MockServerHandler)
        try:
            http_cfg = work_dir / "config_http_302.yaml"
            http_cfg.write_text(f"""endpoint: "http://127.0.0.1:{http_port}/redirect"
timeout_ms: 2000
max_retries: 3
""", encoding="utf-8")
            start_t = time.time()
            res = run_cmd([str(notifier_bin), "--config", str(http_cfg), "--event", str(sample_event), "send"], check=False)
            elapsed = time.time() - start_t
            assert res.returncode == 1
            assert "redirect status 302" in res.stdout or "redirect status 302" in res.stderr
            assert elapsed < 1.0, f"302 status-first rejection should be instant (took {elapsed:.2f}s)"
            with MockServerHandler.lock:
                assert len(MockServerHandler.recorded_requests) == 1
        finally:
            http_server.shutdown()

        log("=== Stage 15: 400 & 429 Client Error Immediate Abort (No Retry) ===")
        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence = [(429, b'{"error":"too_many_requests"}', {}, False)]
        http_server, http_port, _ = run_http_server(MockServerHandler)
        try:
            http_cfg = work_dir / "config_http_429.yaml"
            http_cfg.write_text(f"""endpoint: "http://127.0.0.1:{http_port}/webhook"
timeout_ms: 2000
max_retries: 3
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(http_cfg), "--event", str(sample_event), "send"], check=False)
            assert res.returncode == 1
            assert "client/policy error status 429" in res.stdout or "client/policy error status 429" in res.stderr
            with MockServerHandler.lock:
                assert len(MockServerHandler.recorded_requests) == 1
        finally:
            http_server.shutdown()

        log("=== Stage 16: 500 Server Error Retry Recovery ===")
        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence = [
            (500, b'{"error":"internal_1"}', {}, False),
            (500, b'{"error":"internal_2"}', {}, False),
            (200, b'{"status":"recovered"}', {}, False)
        ]
        http_server, http_port, _ = run_http_server(MockServerHandler)
        try:
            http_cfg = work_dir / "config_http_retry.yaml"
            http_cfg.write_text(f"""endpoint: "http://127.0.0.1:{http_port}/recover"
timeout_ms: 2000
max_retries: 3
backoff_ms: 50
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(http_cfg), "--event", str(sample_event), "send"])
            assert res.returncode == 0
            assert "[SUCCESS]" in res.stdout
            assert "Attempts: 3" in res.stdout
            with MockServerHandler.lock:
                assert len(MockServerHandler.recorded_requests) == 3
        finally:
            http_server.shutdown()

        log("=== Stage 17: 503 Retry Exhaustion ===")
        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence = [
            (503, b'{"error":"unavailable_1"}', {}, False),
            (503, b'{"error":"unavailable_2"}', {}, False),
            (503, b'{"error":"unavailable_3"}', {}, False)
        ]
        http_server, http_port, _ = run_http_server(MockServerHandler)
        try:
            http_cfg = work_dir / "config_http_exhaust.yaml"
            http_cfg.write_text(f"""endpoint: "http://127.0.0.1:{http_port}/fail"
timeout_ms: 2000
max_retries: 2
backoff_ms: 30
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(http_cfg), "--event", str(sample_event), "send"], check=False)
            assert res.returncode == 1
            assert "all 3 attempts exhausted" in res.stdout
            with MockServerHandler.lock:
                assert len(MockServerHandler.recorded_requests) == 3
        finally:
            http_server.shutdown()

        log("=== Stage 18: Exact 1 MiB Body Limit Boundary & Non-Aligned Chunking Tests ===")
        # 18.1 Content-Length: Exactly 1,048,576 bytes -> OK
        exact_1mb_bytes = b"A" * 1048576
        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence = [(200, exact_1mb_bytes, {"Content-Type": "application/octet-stream"}, False)]
        http_server, http_port, _ = run_http_server(MockServerHandler)
        try:
            http_cfg = work_dir / "config_1mb_ok.yaml"
            http_cfg.write_text(f"""endpoint: "http://127.0.0.1:{http_port}/1mb_ok"
timeout_ms: 4000
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(http_cfg), "--event", str(sample_event), "send"])
            assert res.returncode == 0
            assert "[SUCCESS]" in res.stdout
        finally:
            http_server.shutdown()

        # 18.2 Content-Length: 1,048,577 bytes (1 MiB + 1B) -> FAIL (Non-retryable 1 attempt)
        over_1mb_bytes = b"A" * 1048577
        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence = [(200, over_1mb_bytes, {"Content-Type": "application/octet-stream"}, False)]
        http_server, http_port, _ = run_http_server(MockServerHandler)
        try:
            http_cfg = work_dir / "config_1mb_fail.yaml"
            http_cfg.write_text(f"""endpoint: "http://127.0.0.1:{http_port}/1mb_fail"
timeout_ms: 4000
max_retries: 3
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(http_cfg), "--event", str(sample_event), "send"], check=False)
            assert res.returncode == 1
            assert "exceeded 1 MiB limit" in res.stdout or "exceeded 1 MiB limit" in res.stderr
            with MockServerHandler.lock:
                assert len(MockServerHandler.recorded_requests) == 1, "2xx body exceed must fail non-retryable without re-delivery"
        finally:
            http_server.shutdown()

        # 18.3 Non-aligned chunking: 1,048,575 bytes first chunk + 2 bytes trailing -> FAIL
        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence = [(200, over_1mb_bytes, {"Content-Type": "application/octet-stream"}, [1048575, 2])]
        http_server, http_port, _ = run_http_server(MockServerHandler)
        try:
            http_cfg = work_dir / "config_chunk_nonaligned.yaml"
            http_cfg.write_text(f"""endpoint: "http://127.0.0.1:{http_port}/chunk_nonaligned"
timeout_ms: 4000
max_retries: 3
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(http_cfg), "--event", str(sample_event), "send"], check=False)
            assert res.returncode == 1
            assert "exceeded 1 MiB limit" in res.stdout or "exceeded 1 MiB limit" in res.stderr
            with MockServerHandler.lock:
                assert len(MockServerHandler.recorded_requests) == 1
        finally:
            http_server.shutdown()

        log("=== Stage 19: Real TLS / HTTPS Delivery & Precision SAN Tests ===")
        # 19.1 Valid localhost TLS cert
        cert_file = work_dir / "test_server.crt"
        key_file = work_dir / "test_server.key"
        generate_cert(cert_file, key_file, san_list=["DNS.1 = localhost", "IP.1 = 127.0.0.1"], common_name="localhost")

        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence.clear()
        https_server, https_port, _ = run_http_server(MockServerHandler, is_ssl=True, cert_path=cert_file, key_path=key_file)
        try:
            https_cfg = work_dir / "config_https.yaml"
            https_cfg.write_text(f"""endpoint: "https://localhost:{https_port}/secure/webhook"
timeout_ms: 4000
ca_file: "{cert_file}"
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(https_cfg), "--event", str(sample_event), "send"])
            assert res.returncode == 0
            assert "[SUCCESS]" in res.stdout
            assert f"Idempotency-Key: {expected_sha}" in res.stdout

            # 19.2 Without ca_file -> Fail closed
            https_untrusted_cfg = work_dir / "config_https_untrusted.yaml"
            https_untrusted_cfg.write_text(f"""endpoint: "https://localhost:{https_port}/secure/webhook"
timeout_ms: 1500
max_retries: 1
backoff_ms: 20
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(https_untrusted_cfg), "--event", str(sample_event), "send"], check=False)
            assert res.returncode == 1
            assert "TLS negotiation failed" in res.stdout or "Stream/TLS negotiation failed" in res.stdout or "all 2 attempts exhausted" in res.stdout
        finally:
            https_server.shutdown()

        # 19.3 Negative test: Cert SAN has ONLY example.com (strictly no localhost, no 127.0.0.1)
        mismatch_cert = work_dir / "mismatch_server.crt"
        mismatch_key = work_dir / "mismatch_server.key"
        generate_cert(mismatch_cert, mismatch_key, san_list=["DNS.1 = example.com"], common_name="example.com")

        MockServerHandler.recorded_requests.clear()
        MockServerHandler.response_sequence.clear()
        mismatch_server, mismatch_port, _ = run_http_server(MockServerHandler, is_ssl=True, cert_path=mismatch_cert, key_path=mismatch_key)
        try:
            https_mismatch_cfg = work_dir / "config_https_mismatch.yaml"
            https_mismatch_cfg.write_text(f"""endpoint: "https://localhost:{mismatch_port}/secure/webhook"
timeout_ms: 2000
max_retries: 1
backoff_ms: 20
ca_file: "{mismatch_cert}"
""", encoding="utf-8")
            res = run_cmd([str(notifier_bin), "--config", str(https_mismatch_cfg), "--event", str(sample_event), "send"], check=False)
            assert res.returncode == 1
            assert "TLS negotiation failed" in res.stdout or "Stream/TLS negotiation failed" in res.stdout or "all 2 attempts exhausted" in res.stdout
        finally:
            mismatch_server.shutdown()

        log("=== Stage 20: Manifest, CLI --version, User-Agent & README Consistency ===")
        # Check package.tk version
        pkg_content = (repo_root / "package.tk").read_text(encoding="utf-8")
        assert 'version = "0.1.2"' in pkg_content, "package.tk must declare version 0.1.2"

        # Check README.md
        readme_content = (repo_root / "README.md").read_text(encoding="utf-8")
        assert 'notifier = "notifier:0.1.2"' in readme_content, "README.md must guide installation of notifier:0.1.2"
        assert "notifier:0.1.0" not in readme_content, "README.md must not contain stale 0.1.0 reference"

        # Check binary --version
        res = run_cmd([str(notifier_bin), "--version"])
        assert "notifier 0.1.2" in res.stdout, "--version output must match package manifest version 0.1.2"

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    log("==========================================================")
    log("ALL 20 RC6 QUALIFICATION STAGES PASSED FOR tokalang/notifier")
    log("==========================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())

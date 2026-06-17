from __future__ import annotations

import gzip
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zlib
from typing import Any, Dict, Optional


HOP_BY_HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def parse_raw_request(raw_text: str, default_scheme: str = "https") -> Dict[str, Any]:
    normalized = raw_text.replace("\r\n", "\n")
    parts = normalized.split("\n\n", 1)
    head = parts[0].splitlines() if parts and parts[0].strip() else []
    body = parts[1] if len(parts) > 1 else ""
    if not head:
        raise ValueError("Request is empty.")
    request_line = head[0].strip()
    chunks = request_line.split()
    if len(chunks) < 2:
        raise ValueError("Request line must include METHOD and URL.")
    method = chunks[0].upper()
    url = chunks[1].strip()
    headers: Dict[str, str] = {}
    for line in head[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if not key:
            continue
        headers[key] = value.strip()
    if not url.startswith(("http://", "https://")):
        host = headers.get("Host", "").strip() or headers.get(":authority", "").strip()
        if not host:
            raise ValueError("Relative URL requires Host header.")
        if not url.startswith("/"):
            url = "/" + url
        scheme = headers.get(":scheme", "").strip() or headers.get("X-Forwarded-Proto", "").strip() or default_scheme
        scheme = scheme if scheme in ("http", "https") else default_scheme
        url = f"{scheme}://{host}{url}"
    return {"method": method, "url": url, "headers": headers, "body": body}


def send_request_payload(payload: Dict[str, Any], timeout: int = 25) -> Dict[str, Any]:
    method = str(payload.get("method", "GET") or "GET").upper()
    url = str(payload.get("url", "") or "").strip()
    headers = payload.get("headers", {}) or {}
    body = payload.get("body", "") or ""
    if not url:
        raise ValueError("URL is empty.")
    data = _encode_body(body, headers) if body else None
    req = urllib.request.Request(url=url, data=data, method=method)
    _apply_replay_headers(req, headers)
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            raw_bytes = resp.read()
            response_headers = dict(resp.getheaders())
            return {
                "status": resp.status,
                "reason": getattr(resp, "reason", ""),
                "headers": response_headers,
                "body": _decode_response(raw_bytes, response_headers, resp.headers.get_content_charset()),
                "url": resp.geturl(),
            }
    except urllib.error.HTTPError as exc:
        raw_bytes = exc.read() if hasattr(exc, "read") else b""
        response_headers = dict(exc.headers.items()) if exc.headers else {}
        return {
            "status": exc.code,
            "reason": str(exc.reason),
            "headers": response_headers,
            "body": _decode_response(raw_bytes, response_headers),
            "url": url,
        }


def send_raw_request(raw_text: str, timeout: int = 25) -> Dict[str, Any]:
    return send_request_payload(parse_raw_request(raw_text), timeout=timeout)


def render_response(result: Dict[str, Any]) -> str:
    lines = [f"HTTP/1.1 {result.get('status', '')} {result.get('reason', '')}".strip()]
    for key, value in (result.get("headers", {}) or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")
    lines.append(str(result.get("body", "") or ""))
    return "\n".join(lines)


def _apply_replay_headers(req: urllib.request.Request, headers: Dict[str, Any]) -> None:
    added_accept_encoding = False
    for key, value in headers.items():
        header_name = str(key).strip()
        header_value = str(value)
        lower = header_name.lower()
        if not header_name or lower in HOP_BY_HOP_HEADERS or header_name.startswith(":"):
            continue
        if lower == "accept-encoding":
            added_accept_encoding = True
            req.add_header("Accept-Encoding", "identity")
            continue
        if not re.match(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$", header_name):
            continue
        req.add_header(header_name, header_value)
    if not added_accept_encoding:
        req.add_header("Accept-Encoding", "identity")


def _encode_body(body: Any, headers: Dict[str, Any]) -> bytes:
    if isinstance(body, bytes):
        return body
    charset = "utf-8"
    content_type = ""
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            content_type = str(value)
            break
    match = re.search(r"charset=([^;\s]+)", content_type, re.IGNORECASE)
    if match:
        charset = match.group(1).strip("\"'")
    return str(body).encode(charset, errors="replace")


def _decode_response(raw_bytes: bytes, headers: Dict[str, Any], charset: Optional[str] = None) -> str:
    encoding = ""
    for key, value in headers.items():
        if str(key).lower() == "content-encoding":
            encoding = str(value).lower()
            break
    try:
        if "gzip" in encoding:
            raw_bytes = gzip.decompress(raw_bytes)
        elif "deflate" in encoding:
            raw_bytes = zlib.decompress(raw_bytes)
        elif "br" in encoding:
            try:
                import brotli  # type: ignore

                raw_bytes = brotli.decompress(raw_bytes)
            except Exception:
                pass
    except Exception:
        pass
    return raw_bytes.decode(charset or _charset_from_headers(headers) or "utf-8", errors="replace")


def _charset_from_headers(headers: Dict[str, Any]) -> Optional[str]:
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            match = re.search(r"charset=([^;\s]+)", str(value), re.IGNORECASE)
            if match:
                return match.group(1).strip("\"'")
    return None

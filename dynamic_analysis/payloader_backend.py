from __future__ import annotations

import re
import time
from itertools import product
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import QThread, Signal

from .http_replay import parse_raw_request, render_response, send_raw_request


class IntruderAttackWorker(QThread):
    progress = Signal(dict)
    finished_summary = Signal(dict)

    def __init__(
        self,
        raw_request_template: str,
        payloads: List[str],
        timeout_secs: int = 20,
        delay_ms: int = 0,
        payloads_list2: Optional[List[str]] = None,
    ):
        super().__init__()
        self.raw_request_template = raw_request_template
        self.payloads = payloads
        self.payloads_list2 = payloads_list2 or []
        self.timeout_secs = max(1, int(timeout_secs))
        self.delay_ms = max(0, int(delay_ms))
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        payload_pairs = self._build_payload_pairs()
        total = len(payload_pairs)
        sent = 0
        for idx, (payload_1, payload_2) in enumerate(payload_pairs, start=1):
            if self._stop_requested:
                break
            request_text = self._apply_payloads(self.raw_request_template, payload_1, payload_2)
            started = time.time()
            result = self._send_raw_request(request_text)
            elapsed_ms = int((time.time() - started) * 1000)
            sent += 1
            self.progress.emit({
                "index": idx,
                "total": total,
                "payload": payload_1 if payload_2 is None else f"{payload_1} | {payload_2}",
                "request": request_text,
                "response": self._render_response(result),
                "status": result.get("status", "ERR"),
                "elapsed_ms": elapsed_ms,
            })
            if self.delay_ms > 0 and not self._stop_requested:
                self.msleep(self.delay_ms)
        self.finished_summary.emit({"total": total, "sent": sent, "stopped": self._stop_requested})

    def _build_payload_pairs(self) -> List[Tuple[str, Optional[str]]]:
        if not self.payloads:
            return []
        if self.payloads_list2:
            return [(p1, p2) for p1, p2 in product(self.payloads, self.payloads_list2)]
        return [(p1, None) for p1 in self.payloads]

    def _apply_payloads(self, request_template: str, payload_1: str, payload_2: Optional[str]) -> str:
        replaced = request_template
        replaced = replaced.replace("§PAYLOAD§", "__PAYLOAD__")
        replaced = re.sub(r"§[^§]*§", "__PAYLOAD__", replaced)
        replaced = re.sub(r"__[^_]+__", "__PAYLOAD__", replaced)
        if payload_2 is None:
            return replaced.replace("__PAYLOAD__", payload_1)

        marker_index = 0

        def _replace_match(_: re.Match) -> str:
            nonlocal marker_index
            marker_index += 1
            return payload_1 if marker_index == 1 else payload_2

        return re.sub(r"__PAYLOAD__", _replace_match, replaced)

    def _parse_raw_request(self, raw_text: str) -> Dict[str, Any]:
        return parse_raw_request(raw_text)

    def _send_raw_request(self, request_text: str) -> Dict[str, Any]:
        try:
            return send_raw_request(request_text, timeout=self.timeout_secs)
        except Exception as exc:
            return {"status": "ERR", "reason": str(exc), "headers": {}, "body": "", "url": ""}

    def _render_response(self, result: Dict[str, Any]) -> str:
        return render_response(result)

"""
MobHound Scanner - Static Engine
===================================
Coordinates all static analysis detectors and engines.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

from scanner.models import Finding, FindingSource, Severity
from scanner.detectors.manifest_detector   import ManifestDetector
from scanner.detectors.secret_detector     import SecretDetector
from scanner.detectors.crypto_detector     import CryptoDetector
from scanner.detectors.permission_detector import PermissionWebViewDetector
from scanner.detectors.api_detector        import APIDetector
from scanner.detectors.auth_detector       import AuthDetector
from scanner.detectors.storage_detector    import StorageDetector
from scanner.detectors.malware_detector    import MalwareDetector
from scanner.engines.signature_engine      import SignatureEngine
from scanner.engines.heuristic_engine      import HeuristicEngine

logger = logging.getLogger("mobhound.scanner.static")


class StaticEngine:
    """Run all static detectors and return combined findings."""

    def run(
        self,
        jadx_dir:       Optional[Path]         = None,
        manifest_path:  Optional[Path]         = None,
        manifest_elem:  Optional[ET.Element]   = None,
        re_output:      Optional[Any]          = None,
        re_output_raw:  Optional[Dict[str, Any]] = None,
        traffic_flows:  Optional[List[Dict]]   = None,
    ) -> List[Finding]:

        findings: List[Finding] = []

        # ── 1. Manifest ──────────────────────────────────────
        manifest_det = ManifestDetector(
            manifest_path=manifest_path,
            manifest_element=manifest_elem,
        )
        mf = manifest_det.run()
        findings += mf
        logger.info("Manifest: %d findings", len(mf))

        # Extract manifest data for other detectors
        declared_permissions = self._extract_permissions(manifest_elem, manifest_path)
        exported_count, total_comp = self._count_components(manifest_elem, manifest_path)

        # ── 2. Secret detection ──────────────────────────────
        secret_det = SecretDetector(scan_root=jadx_dir)
        sf = secret_det.run()
        findings += sf
        logger.info("Secrets: %d findings", len(sf))

        # ── 3. Crypto ────────────────────────────────────────
        crypto_det = CryptoDetector(scan_root=jadx_dir)
        cf = crypto_det.run()
        findings += cf
        logger.info("Crypto: %d findings", len(cf))

        # ── 4. Permission + WebView + Storage ────────────────
        perm_det = PermissionWebViewDetector(scan_root=jadx_dir)
        pf = perm_det.run()
        findings += pf
        logger.info("Permission/WebView: %d findings", len(pf))

        # ── 5. API misuse ────────────────────────────────────
        api_det = APIDetector(scan_root=jadx_dir)
        af = api_det.run()
        findings += af
        logger.info("API: %d findings", len(af))

        # ── 6. Auth weaknesses ───────────────────────────────
        auth_det = AuthDetector(scan_root=jadx_dir, traffic_flows=traffic_flows)
        authf = auth_det.run()
        findings += authf
        logger.info("Auth: %d findings", len(authf))

        # ── 7. Storage ───────────────────────────────────────
        storage_det = StorageDetector(scan_root=jadx_dir)
        stf = storage_det.run()
        findings += stf
        logger.info("Storage: %d findings", len(stf))

        # ── 8. Malware behavioral ────────────────────────────
        malware_det = MalwareDetector(
            scan_root=jadx_dir,
            declared_permissions=declared_permissions,
        )
        mlf = malware_det.run()
        findings += mlf
        logger.info("Malware: %d findings", len(mlf))

        # ── 9. Known CVE signatures ──────────────────────────
        sig_eng = SignatureEngine(scan_root=jadx_dir)
        sigf = sig_eng.run()
        findings += sigf
        logger.info("Signatures: %d findings", len(sigf))

        # ── 10. Heuristic engine ─────────────────────────────
        heur_eng = HeuristicEngine(
            scan_root=jadx_dir,
            declared_permissions=declared_permissions,
            exported_count=exported_count,
            total_components=total_comp,
            static_findings=findings,
        )
        hf = heur_eng.run()
        findings += hf
        logger.info("Heuristic: %d findings", len(hf))

        # ── 11. RE module output ─────────────────────────────
        if re_output is not None:
            ref = self._convert_re_output(re_output)
            findings += ref
            logger.info("RE module: %d findings", len(ref))
        elif re_output_raw:
            ref = self._convert_re_raw(re_output_raw)
            findings += ref

        logger.info("Static engine total: %d findings", len(findings))
        return findings

    # ─── Helpers ─────────────────────────────────────────────

    def _extract_permissions(
        self,
        elem: Optional[ET.Element],
        path: Optional[Path],
    ) -> List[str]:
        root = self._get_manifest_root(elem, path)
        if root is None:
            return []
        ns = "http://schemas.android.com/apk/res/android"
        perms = []
        for p in root.findall("uses-permission"):
            name = p.get(f"{{{ns}}}name") or p.get("name") or ""
            if name:
                perms.append(name.split(".")[-1])
        return perms

    def _count_components(
        self,
        elem: Optional[ET.Element],
        path: Optional[Path],
    ):
        root = self._get_manifest_root(elem, path)
        if root is None:
            return 0, 0
        app = root.find("application")
        if app is None:
            return 0, 0

        ns = "http://schemas.android.com/apk/res/android"
        tags = ["activity", "service", "receiver", "provider"]
        total, exported = 0, 0
        for tag in tags:
            for comp in app.findall(tag):
                total += 1
                exp = comp.get(f"{{{ns}}}exported") or comp.get("exported")
                has_filter = comp.find("intent-filter") is not None
                if exp == "true" or (exp is None and has_filter):
                    exported += 1
        return exported, total

    @staticmethod
    def _get_manifest_root(
        elem: Optional[ET.Element],
        path: Optional[Path],
    ) -> Optional[ET.Element]:
        if elem is not None:
            return elem
        if path and path.exists():
            try:
                return ET.parse(str(path)).getroot()
            except ET.ParseError:
                pass
        return None

    def _convert_re_output(self, re_output: Any) -> List[Finding]:
        result = []
        for ref in getattr(re_output, "findings", []):
            sev = Severity.MEDIUM
            rel = getattr(ref, "security_relevance", "").lower()
            if "critical" in rel: sev = Severity.CRITICAL
            elif "high" in rel:   sev = Severity.HIGH
            elif "low" in rel:    sev = Severity.LOW
            result.append(Finding(
                title=getattr(ref, "title", "RE Finding"),
                description=getattr(ref, "summary", ""),
                severity=sev,
                confidence=float(getattr(ref, "confidence", 0.5)),
                source=FindingSource.STATIC,
                category="Reverse Engineering",
                evidence=[rel],
                recommendation="Review decompiled code for this finding.",
                tags=["from_re_module"],
            ))
        return result

    def _convert_re_raw(self, raw: Dict[str, Any]) -> List[Finding]:
        result = []
        for ref in raw.get("findings", []):
            result.append(Finding(
                title=ref.get("title", "RE Finding"),
                description=ref.get("summary", ""),
                severity=Severity.MEDIUM,
                confidence=float(ref.get("confidence", 0.5)),
                source=FindingSource.STATIC,
                category="Reverse Engineering",
                tags=["from_re_module"],
            ))
        return result

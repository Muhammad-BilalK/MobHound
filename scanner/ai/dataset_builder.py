"""
MobHound Scanner - AI Dataset Builder
========================================
Builds and maintains the training dataset for the RF classifier.

Sources:
  1. MobHound scan history (real labeled scans)
  2. Synthetic samples from OWASP Mobile Top 10 patterns
  3. Known malware behavioral signatures
  4. NVD CVE feed (online, optional)

Output: scanner/ai/dataset/training_data.jsonl
        Each line: {"features": [...], "label": "HIGH_RISK"}
"""

from __future__ import annotations

import json
import logging
import random
import time
import urllib.request
import urllib.error
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanner.models import FeatureVector, ScanResult

logger = logging.getLogger("mobhound.scanner.ai.dataset")

LABEL_MAP = {
    "CRITICAL_RISK": 0,
    "HIGH_RISK":     1,
    "MEDIUM_RISK":   2,
    "LOW_RISK":      3,
}

DATASET_FILE = "training_data.jsonl"
STATS_FILE   = "dataset_stats.json"


class DatasetBuilder:
    """Build and update the AI training dataset."""

    def __init__(self, dataset_dir: Path):
        self._dir   = dataset_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path  = self._dir / DATASET_FILE
        self._stats = self._dir / STATS_FILE

    # ─── Public API ───────────────────────────────────────────

    def build_synthetic_dataset(self) -> int:
        """
        Generate a synthetic dataset from known security patterns.
        Returns number of samples written.
        """
        samples = []
        samples += self._generate_critical_samples()
        samples += self._generate_high_samples()
        samples += self._generate_medium_samples()
        samples += self._generate_low_samples()

        # Shuffle for balanced training
        random.shuffle(samples)

        written = 0
        with open(self._path, "w", encoding="utf-8") as f:
            for fv, label in samples:
                row = {"features": fv.to_list(), "label": label}
                f.write(json.dumps(row) + "\n")
                written += 1

        self._save_stats(written, samples)
        logger.info("Synthetic dataset built: %d samples → %s", written, self._path)
        return written

    def append_from_scan(self, result: ScanResult, label: Optional[str] = None) -> None:
        """
        Add a real scan result to the dataset.
        If label is None, it is inferred from ai_risk_label.
        """
        if result.feature_vector is None:
            logger.warning("ScanResult has no feature_vector — skipping")
            return

        effective_label = label or result.ai_risk_label
        if effective_label not in LABEL_MAP:
            logger.warning("Unknown label '%s' — skipping", effective_label)
            return

        row = {
            "features":   result.feature_vector.to_list(),
            "label":      effective_label,
            "scan_id":    result.scan_id,
            "package":    result.package_name,
            "timestamp":  result.scan_started,
        }
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        logger.info("Appended scan %s (label=%s) to dataset", result.scan_id[:8], effective_label)

    def load(self) -> Tuple[List[List[float]], List[str]]:
        """Load dataset → (X, y) lists."""
        X, y = [], []
        if not self._path.exists():
            return X, y
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    X.append(row["features"])
                    y.append(row["label"])
                except (json.JSONDecodeError, KeyError):
                    pass
        return X, y

    def stats(self) -> Dict[str, Any]:
        """Return dataset statistics."""
        X, y = self.load()
        counts = {}
        for label in y:
            counts[label] = counts.get(label, 0) + 1
        return {"total": len(X), "distribution": counts}

    def fetch_nvd_samples(self, max_cves: int = 50) -> int:
        """
        Fetch recent Android CVEs from NVD API and add synthetic
        feature vectors based on CVE severity.
        Requires internet access.
        """
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            "?keywordSearch=Android&resultsPerPage=50&noRejected"
        )
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MobHound/2.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            logger.warning("NVD fetch failed: %s — using synthetic data only", e)
            return 0

        written = 0
        for item in data.get("vulnerabilities", [])[:max_cves]:
            cve   = item.get("cve", {})
            metrics = cve.get("metrics", {})

            # Get CVSS score
            score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                    break

            # Map CVSS score → risk label
            if score >= 9.0:
                label = "CRITICAL_RISK"
            elif score >= 7.0:
                label = "HIGH_RISK"
            elif score >= 4.0:
                label = "MEDIUM_RISK"
            else:
                label = "LOW_RISK"

            # Build a synthetic feature vector based on CVE type
            desc = cve.get("descriptions", [{}])[0].get("value", "").lower()
            fv   = self._fv_from_cve_description(desc, score)

            row = {
                "features":  fv.to_list(),
                "label":     label,
                "source":    "nvd",
                "cve_id":    cve.get("id", ""),
                "cvss":      score,
            }
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            written += 1

        logger.info("Added %d NVD-derived samples", written)
        return written

    # ─── Synthetic sample generators ─────────────────────────

    def _generate_critical_samples(self) -> List[Tuple[FeatureVector, str]]:
        samples = []
        label = "CRITICAL_RISK"
        # Spyware profile
        for _ in range(30):
            fv = FeatureVector(
                dangerous_permissions   = random.randint(8, 15),
                exported_components     = random.randint(5, 10),
                hardcoded_secrets       = random.randint(3, 8),
                weak_crypto_count       = random.randint(2, 6),
                ssl_bypass_detected     = 1,
                runtime_secrets_found   = random.randint(3, 8),
                suspicious_traffic      = random.randint(2, 5),
                debuggable              = random.randint(0, 1),
                webview_js_enabled      = 1,
                webview_file_access     = 1,
                dynamic_code_loading    = random.randint(1, 3),
                obfuscation_score       = random.uniform(0.7, 1.0),
                http_usage              = random.randint(3, 8),
                hardcoded_urls          = random.randint(5, 12),
                reflection_usage        = random.randint(2, 5),
            )
            samples.append((fv, label))
        # RCE / malware profile
        for _ in range(20):
            fv = FeatureVector(
                dangerous_permissions   = random.randint(10, 20),
                hardcoded_secrets       = random.randint(5, 10),
                dynamic_code_loading    = random.randint(2, 5),
                ssl_bypass_detected     = 1,
                runtime_secrets_found   = random.randint(5, 10),
                debuggable              = 1,
                obfuscation_score       = random.uniform(0.8, 1.0),
                native_lib_usage        = random.randint(3, 8),
                http_usage              = random.randint(5, 10),
            )
            samples.append((fv, label))
        return samples

    def _generate_high_samples(self) -> List[Tuple[FeatureVector, str]]:
        samples = []
        label = "HIGH_RISK"
        for _ in range(50):
            fv = FeatureVector(
                dangerous_permissions   = random.randint(4, 8),
                exported_components     = random.randint(2, 5),
                weak_crypto_count       = random.randint(1, 4),
                hardcoded_secrets       = random.randint(1, 3),
                ssl_bypass_detected     = random.randint(0, 1),
                runtime_secrets_found   = random.randint(1, 4),
                webview_js_enabled      = random.randint(0, 1),
                http_usage              = random.randint(1, 4),
                debuggable              = random.randint(0, 1),
                obfuscation_score       = random.uniform(0.3, 0.7),
                dynamic_code_loading    = random.randint(0, 2),
            )
            samples.append((fv, label))
        return samples

    def _generate_medium_samples(self) -> List[Tuple[FeatureVector, str]]:
        samples = []
        label = "MEDIUM_RISK"
        for _ in range(60):
            fv = FeatureVector(
                dangerous_permissions   = random.randint(2, 5),
                exported_components     = random.randint(1, 3),
                weak_crypto_count       = random.randint(0, 2),
                hardcoded_secrets       = random.randint(0, 1),
                ssl_bypass_detected     = 0,
                runtime_secrets_found   = random.randint(0, 2),
                webview_js_enabled      = random.randint(0, 1),
                http_usage              = random.randint(0, 2),
                debuggable              = random.randint(0, 1),
                backup_enabled          = random.randint(0, 1),
                obfuscation_score       = random.uniform(0.1, 0.4),
            )
            samples.append((fv, label))
        return samples

    def _generate_low_samples(self) -> List[Tuple[FeatureVector, str]]:
        samples = []
        label = "LOW_RISK"
        for _ in range(40):
            fv = FeatureVector(
                dangerous_permissions   = random.randint(0, 2),
                exported_components     = random.randint(0, 1),
                weak_crypto_count       = 0,
                hardcoded_secrets       = 0,
                ssl_bypass_detected     = 0,
                runtime_secrets_found   = 0,
                webview_js_enabled      = 0,
                http_usage              = 0,
                debuggable              = 0,
                backup_enabled          = random.randint(0, 1),
                obfuscation_score       = random.uniform(0.0, 0.2),
            )
            samples.append((fv, label))
        return samples

    # ─── CVE description → feature vector ────────────────────

    @staticmethod
    def _fv_from_cve_description(desc: str, score: float) -> FeatureVector:
        fv = FeatureVector()
        if "sql injection"      in desc: fv.sql_queries_seen       = random.randint(2, 5)
        if "ssl" in desc or "tls" in desc: fv.ssl_bypass_detected  = 1
        if "hardcoded"          in desc: fv.hardcoded_secrets       = random.randint(1, 4)
        if "webview"            in desc: fv.webview_js_enabled      = 1
        if "crypto" in desc or "cipher" in desc: fv.weak_crypto_count = random.randint(1, 3)
        if "permission"         in desc: fv.dangerous_permissions   = random.randint(3, 8)
        if "exported"           in desc: fv.exported_components     = random.randint(2, 5)
        if "remote code"        in desc: fv.dynamic_code_loading    = random.randint(1, 3)
        if "information"        in desc: fv.runtime_secrets_found   = random.randint(1, 3)
        # Scale by CVSS
        scale = score / 10.0
        fv.dangerous_permissions = max(fv.dangerous_permissions, int(score))
        return fv

    # ─── Stats ───────────────────────────────────────────────

    def _save_stats(self, total: int, samples: List) -> None:
        counts: Dict[str, int] = {}
        for _, label in samples:
            counts[label] = counts.get(label, 0) + 1
        stats = {
            "total":        total,
            "distribution": counts,
            "feature_names": FeatureVector.feature_names(),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with open(self._stats, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)

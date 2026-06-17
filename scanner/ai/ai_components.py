"""
MobHound Scanner - AI Components
====================================
Standalone AI pipeline files:
  - FeatureExtractor
  - ModelTrainer
  - RiskPredictor
  - RiskClassifier
"""

from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanner.models import FeatureVector, Finding, FindingSource, DetectorType, Severity

logger = logging.getLogger("mobhound.scanner.ai")

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import cross_val_score
    from sklearn.metrics import classification_report
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not installed – heuristic mode only")


# ── feature_extractor.py ──────────────────────────────────────

class FeatureExtractor:
    """
    Builds a FeatureVector from scan findings and manifest/runtime data.
    This is the canonical feature extractor used by the AI pipeline.
    """

    def extract(
        self,
        static_findings:  List[Finding],
        dynamic_findings: List[Finding],
        manifest_data:    Optional[Dict[str, Any]] = None,
        frida_events:     Optional[List[Dict]]     = None,
    ) -> FeatureVector:
        fv = FeatureVector()
        manifest_data = manifest_data or {}
        frida_events  = frida_events  or []

        # Manifest data
        fv.dangerous_permissions = int(manifest_data.get("dangerous_permission_count", 0))
        fv.exported_components   = int(manifest_data.get("exported_component_count", 0))
        fv.debuggable            = 1 if manifest_data.get("debuggable") else 0
        fv.backup_enabled        = 1 if manifest_data.get("backup_enabled", True) else 0

        # Static findings
        for f in static_findings:
            t = f.title.lower()
            d = f.detector

            if d == DetectorType.CRYPTO:
                fv.weak_crypto_count += 1
                if "random" in t:    fv.insecure_random += 1

            if d == DetectorType.SECRET:
                fv.hardcoded_secrets += 1

            if d == DetectorType.WEBVIEW:
                if "javascript"  in t: fv.webview_js_enabled  = 1
                if "file access" in t: fv.webview_file_access  = 1

            if "http://"    in t or "cleartext" in t: fv.http_usage            += 1
            if "reflection" in t:                     fv.reflection_usage      += 1
            if "dynamic"    in t and "code" in t:     fv.dynamic_code_loading  += 1
            if "native"     in t and "lib"  in t:     fv.native_lib_usage      += 1
            if "hardcoded"  in t and "url"  in t:     fv.hardcoded_urls        += 1
            if "obfuscat"   in t:
                fv.obfuscation_score = min(1.0, fv.obfuscation_score + 0.2)

        # Dynamic findings
        for f in dynamic_findings:
            t = f.title.lower()
            if "ssl"          in t: fv.ssl_bypass_detected   = 1
            if "root"         in t: fv.root_check_bypassed   = 1
            if "secret" in t or "token" in t or "auth" in t:
                                    fv.runtime_secrets_found += 1
            if "http"         in t and "plain" in t:
                                    fv.suspicious_traffic    += 1
            if "sql"          in t: fv.sql_queries_seen      += 1
            if "file"         in t: fv.file_access_sensitive += 1

        # Boost feature vector based on actual findings severity
        from scanner.models import Severity
        critical_count = sum(1 for f in static_findings + dynamic_findings
                            if f.severity == Severity.CRITICAL)
        high_count     = sum(1 for f in static_findings + dynamic_findings
                            if f.severity == Severity.HIGH)
        fv.exported_components   = max(fv.exported_components,   critical_count * 2)
        fv.dangerous_permissions = max(fv.dangerous_permissions, min(high_count // 5, 15))
        fv.http_usage = max(fv.http_usage, 1 if any(
            "cleartext" in f.title.lower() or ("http" in f.title.lower() and "https" not in f.title.lower())
            for f in static_findings) else 0)

        # Frida events
        for ev in frida_events:
            ev_type = (ev.get("event") or "").upper()
            if "CRYPTO"         in ev_type: fv.crypto_api_calls += 1
            if "IPC" in ev_type or "INTENT" in ev_type: fv.ipc_activity += 1
            if "SQL"            in ev_type: fv.sql_queries_seen += 1

        return fv


# ── model_trainer.py ─────────────────────────────────────────

class ModelTrainer:
    """
    Trains, evaluates, and persists the Random Forest model.
    Supports both RandomForest and GradientBoosting backends.
    """

    MODEL_FILE   = "mobhound_model.pkl"
    ENCODER_FILE = "mobhound_encoder.pkl"
    REPORT_FILE  = "training_report.json"

    def __init__(self, model_dir: Path, algorithm: str = "random_forest"):
        self._dir       = model_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._algo      = algorithm
        self._model_path= model_dir / self.MODEL_FILE
        self._enc_path  = model_dir / self.ENCODER_FILE
        self._rep_path  = model_dir / self.REPORT_FILE

    def train(
        self,
        X: List[List[float]],
        y: List[str],
        evaluate: bool = True,
    ) -> Tuple[Optional[Any], Optional[Any]]:
        if not SKLEARN_AVAILABLE:
            logger.error("scikit-learn not installed")
            return None, None

        if len(X) < 20:
            logger.warning("Only %d samples — need at least 20 to train", len(X))
            return None, None

        encoder = LabelEncoder()
        y_enc   = encoder.fit_transform(y)
        X_arr   = np.array(X, dtype=float)

        if self._algo == "gradient_boosting":
            model = GradientBoostingClassifier(
                n_estimators=200,
                max_depth=5,
                learning_rate=0.1,
                random_state=42,
            )
        else:
            model = RandomForestClassifier(
                n_estimators=300,
                max_depth=12,
                min_samples_split=3,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )

        model.fit(X_arr, y_enc)

        # Cross-validation evaluation
        report_data: Dict[str, Any] = {
            "algorithm":    self._algo,
            "n_samples":    len(X),
            "n_features":   len(X[0]),
            "classes":      list(encoder.classes_),
        }

        if evaluate and len(X) >= 50:
            try:
                cv_scores = cross_val_score(model, X_arr, y_enc, cv=5, scoring="accuracy")
                report_data["cv_accuracy_mean"] = float(cv_scores.mean())
                report_data["cv_accuracy_std"]  = float(cv_scores.std())
                logger.info(
                    "CV accuracy: %.2f ± %.2f",
                    cv_scores.mean(), cv_scores.std()
                )
            except Exception as e:
                logger.warning("CV evaluation failed: %s", e)

        # Feature importance
        if hasattr(model, "feature_importances_"):
            names = FeatureVector.feature_names()
            importances = model.feature_importances_
            report_data["feature_importance"] = {
                names[i]: float(importances[i])
                for i in range(min(len(names), len(importances)))
            }

        # Save model + encoder
        with open(self._model_path, "wb") as f: pickle.dump(model, f)
        with open(self._enc_path,   "wb") as f: pickle.dump(encoder, f)
        with open(self._rep_path,   "w")  as f: json.dump(report_data, f, indent=2)

        logger.info("Model trained on %d samples, saved → %s", len(X), self._model_path)
        return model, encoder

    def load(self) -> Tuple[Optional[Any], Optional[Any]]:
        if not self._model_path.exists() or not self._enc_path.exists():
            return None, None
        try:
            with open(self._model_path, "rb") as f: model   = pickle.load(f)
            with open(self._enc_path,   "rb") as f: encoder = pickle.load(f)
            logger.info("Loaded model from %s", self._model_path)
            return model, encoder
        except Exception as e:
            logger.warning("Model load failed: %s", e)
            return None, None

    def get_training_report(self) -> Optional[Dict[str, Any]]:
        if not self._rep_path.exists():
            return None
        try:
            return json.loads(self._rep_path.read_text())
        except Exception:
            return None


# ── predictor.py ─────────────────────────────────────────────

class RiskPredictor:
    """
    Runs inference using the trained model.
    Falls back to heuristic scoring if model unavailable.
    """

    RISK_LABELS = ["CRITICAL_RISK", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK"]

    def __init__(self, model: Optional[Any] = None, encoder: Optional[Any] = None):
        self._model   = model
        self._encoder = encoder

    def predict(self, fv: FeatureVector) -> Tuple[str, float, Dict[str, float]]:
        """
        Returns:
            (risk_label, confidence, {label: probability})
        """
        if self._model is not None and SKLEARN_AVAILABLE:
            return self._ml_predict(fv)
        return self._heuristic_predict(fv)

    def _ml_predict(self, fv: FeatureVector) -> Tuple[str, float, Dict[str, float]]:
        try:
            confidence_caps = {
                "CRITICAL_RISK": 0.95,
                "HIGH_RISK": 0.88,
                "MEDIUM_RISK": 0.82,
                "LOW_RISK": 0.75,
            }
            X     = np.array([fv.to_list()], dtype=float)
            proba = self._model.predict_proba(X)[0]
            idx   = int(np.argmax(proba))
            label = self._encoder.inverse_transform([idx])[0]
            conf  = min(confidence_caps.get(label, 0.90), float(proba[idx]))
            # Full probability map
            classes   = self._encoder.classes_
            prob_map  = {
                str(classes[i]): min(confidence_caps.get(str(classes[i]), 0.90), float(proba[i]))
                for i in range(len(classes))
            }
            return label, conf, prob_map
        except Exception as e:
            logger.warning("ML predict failed: %s – falling back", e)
            return self._heuristic_predict(fv)

    def _heuristic_predict(self, fv: FeatureVector) -> Tuple[str, float, Dict[str, float]]:
        critical_hits = 0
        high_hits = 0
        medium_hits = 0
        low_hits = 0

        if fv.hardcoded_secrets >= 1:
            critical_hits += int(fv.hardcoded_secrets)
        if fv.ssl_bypass_detected:
            critical_hits += 1
        if fv.runtime_secrets_found >= 2:
            critical_hits += int(fv.runtime_secrets_found)
        if fv.webview_file_access and fv.webview_js_enabled:
            critical_hits += 1
        if fv.debuggable and fv.dangerous_permissions >= 8:
            critical_hits += 1

        if fv.weak_crypto_count >= 1:
            high_hits += int(fv.weak_crypto_count)
        if fv.exported_components >= 3:
            high_hits += 1
        if fv.dynamic_code_loading >= 1:
            high_hits += int(fv.dynamic_code_loading)
        if fv.obfuscation_score >= 0.6 and fv.dynamic_code_loading >= 1:
            high_hits += 1
        if fv.ssl_bypass_detected and fv.runtime_secrets_found >= 1:
            high_hits += 1
        if fv.http_usage >= 2:
            high_hits += 1
        if fv.webview_js_enabled and not fv.webview_file_access:
            high_hits += 1
        if fv.dangerous_permissions >= 6:
            high_hits += 1

        if fv.backup_enabled and fv.dangerous_permissions >= 3:
            medium_hits += 1
        if fv.insecure_random >= 1:
            medium_hits += int(fv.insecure_random)
        if fv.http_usage == 1:
            medium_hits += 1
        if fv.suspicious_traffic >= 1:
            medium_hits += 1
        if 3 <= fv.dangerous_permissions < 6:
            medium_hits += 1
        if 1 <= fv.exported_components < 3:
            medium_hits += 1

        if fv.backup_enabled and fv.dangerous_permissions < 3:
            low_hits += 1
        if fv.debuggable and fv.dangerous_permissions < 4:
            low_hits += 1
        if fv.hardcoded_urls >= 1:
            low_hits += int(fv.hardcoded_urls)
        if fv.reflection_usage >= 1:
            low_hits += 1

        if critical_hits:
            label = "CRITICAL_RISK"
            conf = min(0.98, 0.82 + critical_hits * 0.03)
        elif high_hits >= 2:
            label = "HIGH_RISK"
            conf = min(0.92, 0.72 + high_hits * 0.025 + critical_hits * 0.02)
        elif high_hits >= 1 or medium_hits >= 2:
            label = "MEDIUM_RISK"
            conf = min(0.85, 0.62 + medium_hits * 0.02 + high_hits * 0.01)
        else:
            label = "LOW_RISK"
            conf = min(0.78, 0.50 + low_hits * 0.01 + medium_hits * 0.005)

        remaining = max(0.0, 1.0 - conf)
        others = [risk_label for risk_label in self.RISK_LABELS if risk_label != label]
        label_index = self.RISK_LABELS.index(label)
        weights = []
        for risk_label in others:
            distance = abs(self.RISK_LABELS.index(risk_label) - label_index)
            weights.append(1.0 / max(distance, 1))
        total_weight = sum(weights) or 1.0
        prob_map = {label: round(conf, 3)}
        for risk_label, weight in zip(others, weights):
            prob_map[risk_label] = round(remaining * (weight / total_weight), 3)
        return label, round(conf, 3), prob_map


# ── risk_classifier.py ───────────────────────────────────────

class RiskClassifier:
    """
    High-level risk classifier combining predictor output with
    finding analysis to generate AI-derived findings.
    """

    def classify(
        self,
        label:    str,
        conf:     float,
        prob_map: Dict[str, float],
        fv:       FeatureVector,
    ) -> List[Finding]:
        findings = []

        sev_map = {
            "CRITICAL_RISK": Severity.CRITICAL,
            "HIGH_RISK":     Severity.HIGH,
            "MEDIUM_RISK":   Severity.MEDIUM,
            "LOW_RISK":      Severity.LOW,
        }
        sev = sev_map.get(label, Severity.MEDIUM)

        # Main classification finding
        prob_lines = [f"  {k}: {v:.1%}" for k, v in sorted(
            prob_map.items(), key=lambda x: -x[1]
        )]
        findings.append(Finding(
            title=f"AI Risk Classification: {label}",
            description=(
                f"The MobHound AI engine classified this APK as {label} "
                f"with {conf:.0%} confidence based on {len(FeatureVector.feature_names())} "
                f"extracted features."
            ),
            severity=sev,
            confidence=conf,
            detector=DetectorType.MALWARE,
            source=FindingSource.AI,
            category="AI Risk Assessment",
            owasp_mobile="OWASP Mobile Top 10 (combined)",
            evidence=[
                f"Risk label: {label}",
                f"Confidence: {conf:.1%}",
                "Probability distribution:",
                *prob_lines,
                "",
                "Key risk indicators:",
                f"  Dangerous permissions:  {fv.dangerous_permissions}",
                f"  Hardcoded secrets:      {fv.hardcoded_secrets}",
                f"  Weak crypto:            {fv.weak_crypto_count}",
                f"  SSL bypass:             {'Yes' if fv.ssl_bypass_detected else 'No'}",
                f"  Runtime secrets:        {fv.runtime_secrets_found}",
                f"  Obfuscation score:      {fv.obfuscation_score:.0%}",
            ],
            recommendation=(
                "Address all CRITICAL and HIGH findings first. "
                "Re-run the scanner after fixes to track improvement."
            ),
            raw={"label": label, "confidence": conf, "probabilities": prob_map},
        ))

        # Specific AI observations
        if fv.hardcoded_secrets >= 3:
            findings.append(Finding(
                title="AI: Systemic Secret Management Failure",
                description=(
                    f"The AI detected {fv.hardcoded_secrets} hardcoded secrets. "
                    "This is a systemic issue, not isolated oversights."
                ),
                severity=Severity.CRITICAL,
                confidence=min(0.97, 0.70 + fv.hardcoded_secrets * 0.04),
                detector=DetectorType.SECRET,
                source=FindingSource.AI,
                category="Secret Management",
                cwe_id="CWE-798",
                recommendation="Migrate to Android Keystore + server-side secret management.",
            ))

        if fv.ssl_bypass_detected and fv.runtime_secrets_found >= 2:
            findings.append(Finding(
                title="AI: SSL Bypass + Runtime Secrets — MITM Risk",
                description=(
                    "SSL pinning was bypassed AND secrets were captured at runtime. "
                    "An attacker performing MITM can steal credentials."
                ),
                severity=Severity.CRITICAL,
                confidence=0.93,
                detector=DetectorType.TRAFFIC,
                source=FindingSource.AI,
                category="Credential Interception",
                cwe_id="CWE-319",
                recommendation="Implement proper cert pinning. Rotate all captured credentials.",
            ))

        if fv.obfuscation_score >= 0.7 and fv.dynamic_code_loading >= 1:
            findings.append(Finding(
                title="AI: Heavy Obfuscation + Dynamic Loading — Evasion Risk",
                description=(
                    "The app combines heavy obfuscation with dynamic code loading. "
                    "This is a common malware evasion technique."
                ),
                severity=Severity.HIGH,
                confidence=0.82,
                detector=DetectorType.MALWARE,
                source=FindingSource.AI,
                category="Evasion Technique",
                cwe_id="CWE-693",
                recommendation="Investigate runtime-loaded code. Use dynamic analysis to observe behavior.",
            ))

        if fv.dangerous_permissions >= 8 and fv.http_usage >= 3:
            findings.append(Finding(
                title="AI: Excessive Permissions + Insecure Transport",
                description=(
                    f"App declares {fv.dangerous_permissions} dangerous permissions "
                    f"and uses HTTP for {fv.http_usage} connections. "
                    "Combined, this enables data exfiltration over unencrypted channels."
                ),
                severity=Severity.HIGH,
                confidence=0.85,
                detector=DetectorType.PERMISSION,
                source=FindingSource.AI,
                category="Data Exfiltration Risk",
                cwe_id="CWE-200",
                recommendation="Reduce permissions to minimum required. Enforce HTTPS for all traffic.",
            ))

        return findings

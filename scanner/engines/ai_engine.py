"""
MobHound Scanner - AI Engine (v2)
====================================
Orchestrates the full AI pipeline using properly separated components.
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanner.models import FeatureVector, Finding, ScanResult
from scanner.ai.ai_components import FeatureExtractor, ModelTrainer, RiskPredictor, RiskClassifier
from scanner.ai.dataset_builder import DatasetBuilder

logger = logging.getLogger("mobhound.scanner.ai")

class AIEngine:
    def __init__(self, model_dir: Path):
        self._model_dir   = model_dir
        self._dataset_dir = model_dir / "dataset"
        model_dir.mkdir(parents=True, exist_ok=True)
        self._extractor  = FeatureExtractor()
        self._trainer    = ModelTrainer(model_dir=model_dir)
        self._dataset    = DatasetBuilder(dataset_dir=self._dataset_dir)
        self._classifier = RiskClassifier()
        model, encoder = self._trainer.load()
        if model is None:
            logger.info("No trained model found — bootstrapping with synthetic dataset")
            self._bootstrap()
            model, encoder = self._trainer.load()
        self._predictor = RiskPredictor(model=model, encoder=encoder)

    def extract_features(self, static_findings, dynamic_findings,
                         manifest_data=None, frida_events=None):
        return self._extractor.extract(static_findings, dynamic_findings, manifest_data, frida_events)

    def classify(self, fv):
        label, conf, prob_map = self._predictor.predict(fv)
        findings = self._classifier.classify(label, conf, prob_map, fv)
        return label, conf, findings

    def retrain(self, fetch_nvd=False):
        if fetch_nvd:
            self._dataset.fetch_nvd_samples()
        X, y = self._dataset.load()
        if len(X) < 20:
            self._dataset.build_synthetic_dataset()
            X, y = self._dataset.load()
        model, encoder = self._trainer.train(X, y, evaluate=True)
        if model is None:
            return False
        self._predictor = RiskPredictor(model=model, encoder=encoder)
        return True

    def add_sample(self, result, label=None):
        self._dataset.append_from_scan(result, label)

    def dataset_stats(self):
        return self._dataset.stats()

    def training_report(self):
        return self._trainer.get_training_report()

    def _bootstrap(self):
        n = self._dataset.build_synthetic_dataset()
        logger.info("Built synthetic dataset: %d samples", n)
        X, y = self._dataset.load()
        self._trainer.train(X, y, evaluate=False)

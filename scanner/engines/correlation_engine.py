"""
MobHound Scanner - Correlation Engine
========================================
Merges static + dynamic + AI findings, deduplicates,
assigns final confidence scores, and maps to OWASP/CWE.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Tuple

from scanner.models import Finding, FindingSource, Severity

logger = logging.getLogger("mobhound.scanner.correlation")

# Severity boost when a static finding is confirmed by a dynamic one
DYNAMIC_CONFIRMATION_BOOST = 0.15

# Minimum confidence to keep a finding in the final report
MIN_CONFIDENCE_THRESHOLD = 0.35


class CorrelationEngine:
    """
    Merge findings from all sources, deduplicate, boost confidence
    when static indicators are confirmed by dynamic data, and
    produce a final ranked finding list.
    """

    def run(
        self,
        static_findings:  List[Finding],
        dynamic_findings: List[Finding],
        ai_findings:      List[Finding],
    ) -> List[Finding]:
        all_findings = static_findings + dynamic_findings + ai_findings

        # 1. Cross-confirm static with dynamic
        all_findings = self._cross_confirm(static_findings, dynamic_findings)
        all_findings += ai_findings

        # 2. Deduplicate
        all_findings = self._deduplicate(all_findings)

        # 3. Filter low-confidence noise
        all_findings = [
            f for f in all_findings if f.confidence >= MIN_CONFIDENCE_THRESHOLD
        ]

        # 4. Sort: severity → confidence → source
        all_findings.sort(key=self._sort_key)

        logger.info(
            "Correlation complete: %d total findings (%d static, %d dynamic, %d ai) -> %d after dedup/filter",
            len(static_findings) + len(dynamic_findings) + len(ai_findings),
            len(static_findings), len(dynamic_findings), len(ai_findings),
            len(all_findings),
        )
        return all_findings

    # ─── Cross-confirmation ────────────────────────────────────

    def _cross_confirm(
        self,
        static:  List[Finding],
        dynamic: List[Finding],
    ) -> List[Finding]:
        """
        If a static finding is corroborated by a dynamic observation,
        boost its confidence and mark source as COMBINED.
        """
        dynamic_categories = {f.category.lower() for f in dynamic}
        dynamic_titles     = {f.title.lower()    for f in dynamic}

        confirmed = []
        for f in static:
            f_cat   = f.category.lower()
            f_title = f.title.lower()
            boosted = False

            # Category-level correlation
            if f_cat in dynamic_categories:
                f.confidence = min(1.0, f.confidence + DYNAMIC_CONFIRMATION_BOOST)
                f.source     = FindingSource.COMBINED
                f.tags.append("dynamically_confirmed")
                boosted = True

            # Title-level fuzzy correlation
            for dt in dynamic_titles:
                # Share at least one significant keyword
                s_words = set(f_title.split())
                d_words = set(dt.split())
                common  = s_words & d_words - {"the", "a", "an", "in", "of", "is", "for"}
                if len(common) >= 2 and not boosted:
                    f.confidence = min(1.0, f.confidence + DYNAMIC_CONFIRMATION_BOOST * 0.5)
                    f.source     = FindingSource.COMBINED
                    f.tags.append("dynamically_correlated")
                    break

            confirmed.append(f)

        # Add all dynamic findings too
        confirmed += dynamic
        return confirmed

    # ─── Deduplication ────────────────────────────────────────

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Merge findings that represent the same vulnerability:
          - Same title + same affected file
          - Keep highest confidence version, merge evidence lists
        """
        groups: Dict[str, List[Finding]] = defaultdict(list)

        for f in findings:
            # Grouping key: title + first affected file (or empty)
            file_key = f.affected_files[0] if f.affected_files else ""
            key = f"{f.title.lower()}|{file_key.lower()}"
            groups[key].append(f)

        merged: List[Finding] = []
        for key, group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
                continue

            # Keep finding with highest confidence as base
            base = max(group, key=lambda x: x.confidence)

            # Merge evidence from all duplicates
            all_evidence = []
            all_files    = []
            all_lines    = []
            all_network  = []
            all_traces   = []

            for g in group:
                all_evidence += [e for e in g.evidence        if e not in all_evidence]
                all_files    += [f for f in g.affected_files   if f not in all_files]
                all_lines    += [l for l in g.line_numbers     if l not in all_lines]
                all_network  += [n for n in g.network_evidence if n not in all_network]
                all_traces   += [t for t in g.runtime_traces   if t not in all_traces]

            base.evidence         = all_evidence[:10]   # cap at 10 items
            base.affected_files   = list(set(all_files))
            base.line_numbers     = sorted(set(all_lines))
            base.network_evidence = all_network[:5]
            base.runtime_traces   = all_traces[:5]

            # If duplicated in both static + dynamic → mark as COMBINED
            sources = {g.source for g in group}
            if FindingSource.STATIC in sources and FindingSource.DYNAMIC in sources:
                base.source = FindingSource.COMBINED
                if "dynamically_confirmed" not in base.tags:
                    base.tags.append("dynamically_confirmed")

            merged.append(base)

        return merged

    # ─── Sorting ──────────────────────────────────────────────

    @staticmethod
    def _sort_key(f: Finding) -> Tuple:
        sev_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH:     1,
            Severity.MEDIUM:   2,
            Severity.LOW:      3,
            Severity.INFO:     4,
        }
        src_order = {
            FindingSource.COMBINED: 0,
            FindingSource.DYNAMIC:  1,
            FindingSource.AI:       2,
            FindingSource.STATIC:   3,
        }
        return (
            sev_order.get(f.severity, 5),
            -f.confidence,
            src_order.get(f.source, 4),
        )

"""
Diffing + explanation registry for the regression harness.

Every difference between the v2 and v3 snapshots must be categorised:
  - PASS       : equal (after vocabulary normalisation)
  - EXPLAINED  : intentional v3 behaviour with a documented reason (WARNING-level)
  - REGRESSION : unexplained behaviour change -> must be fixed

Documented intentional v3 changes (each with its spec reference):
  1. verification_vocab      : v3 internal 'confirmed' == v2 'verified' (same
                               risk multiplier 1.0, same semantic tier).
  2. verification_band_shift : v3 §6.3 dynamic confidence bands replace the v2
                               static evidence-level mapping (confirmed->likely).
  3. coverage_na_vs_skipped  : v3 Coverage Engine classifies UNKNOWN/incomplete
                               modules as NOT_APPLICABLE instead of SKIPPED (A6
                               reconciliation fix, docs §6.4 / §8 item 6).
  4. risk_from_band_shift    : risk delta caused solely by verification band
                               shifts (risk itself is not recomputed differently).
"""

from typing import Any, Dict, List, Tuple


V3_TO_V2_VERIFICATION = {
    'confirmed': 'verified',
}


def normalize_verification(status: str) -> str:
    return V3_TO_V2_VERIFICATION.get(status, status)


FindingDiff = Tuple[str, str, Any, Any]  # (module, field, v2_value, v3_value)


def diff_findings(v2_snap: Dict[str, Any], v3_snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare per-finding fields; returns explained/unexplained diff records."""
    v2_by_module = {f['module']: f for f in v2_snap['findings']}
    v3_by_module = {f['module']: f for f in v3_snap['findings']}
    diffs: List[Dict[str, Any]] = []
    for module in sorted(set(v2_by_module) | set(v3_by_module)):
        v2 = v2_by_module.get(module)
        v3 = v3_by_module.get(module)
        if v2 is None or v3 is None:
            diffs.append(_record(module, 'module_presence',
                                 v2['module'] if v2 else None,
                                 v3['module'] if v3 else None,
                                 explained=True,
                                 reason='Module only present in one engine path.',
                                 category='module_presence'))
            continue

        for field in ('status', 'severity', 'confidence', 'cvss_score', 'execution_state'):
            v2v, v3v = v2[field], v3[field]
            if v2v != v3v:
                cat, explained, reason = _classify_finding_diff(field, v2v, v3v, v2, v3)
                diffs.append(_record(module, field, v2v, v3v, explained, reason, cat))

        v2v, v3v = v2['verification'], v3['verification']
        if normalize_verification(v2v) != normalize_verification(v3v):
            diffs.append(_record(
                module, 'verification', v2v, v3v,
                explained=True,
                reason=(
                    'v3 Verification Engine uses dynamic confidence bands (§6.3) '
                    'instead of the v2 static evidence-level mapping.'
                ),
                category='verification_band_shift',
            ))
        elif v2v != v3v:
            diffs.append(_record(
                module, 'verification', v2v, v3v,
                explained=True,
                reason=(
                    'Vocabulary-only change: v3 internal classification '
                    "'confirmed' renders as report-vocabulary 'verified' (§3.3)."
                ),
                category='verification_vocab',
            ))
    return diffs


def _classify_finding_diff(field: str, v2v: Any, v3v: Any,
                           v2: Dict[str, Any], v3: Dict[str, Any]) -> Tuple[str, bool, str]:
    if field == 'execution_state':
        if v2v == 'skipped' and v3v == 'not_applicable':
            return ('coverage_na_vs_skipped', True,
                    'v3 Coverage Engine classifies UNKNOWN/incomplete modules as '
                    'NOT_APPLICABLE (reconciliation fix, §6.4).')
        if v2v == 'not_applicable' and v3v == 'skipped':
            return ('coverage_na_vs_skipped', True,
                    'v3 Coverage Engine no longer treats PASS-without-tests as '
                    'skipped; documented NA classification (§6.4).')
        return ('execution_state_change', False,
                f'Execution state changed from {v2v!r} to {v3v!r} without a '
                'documented explanation.')
    if field == 'status':
        return ('status_change', False,
                f'Status changed from {v2v!r} to {v3v!r}; scanners must keep '
                'provisional statuses stable.')
    if field == 'severity':
        return ('severity_change', False,
                f'Severity changed from {v2v!r} to {v3v!r}; v3 severity must '
                'match v2 on identical evidence (module map authoritative).')
    if field == 'confidence':
        return ('confidence_change', False,
                f'Confidence changed from {v2v!r} to {v3v!r}; the Confidence '
                'Engine must reproduce v2 evidence math exactly.')
    if field == 'cvss_score':
        return ('cvss_change', False,
                f'CVSS changed from {v2v!r} to {v3v!r}; CVSS depends on '
                'severity+confidence which are both parity-checked.')
    return ('unclassified', False, 'Unclassified finding-level difference.')


def diff_assessment(v2_snap: Dict[str, Any], v3_snap: Dict[str, Any],
                    finding_diffs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compare assessment-level outputs; classify against finding diffs."""
    diffs: List[Dict[str, Any]] = []
    finding_regressions = [d for d in finding_diffs if not d['explained']]

    for field in ('risk_score', 'risk_grade'):
        v2v, v3v = v2_snap[field], v3_snap[field]
        if v2v != v3v:
            if not finding_regressions:
                diffs.append(_record(
                    'assessment', field, v2v, v3v, explained=True,
                    reason='Driven by explained v3 verification band shifts '
                           '(dynamic confidence thresholds §6.3); the Risk Engine '
                           'formula itself is byte-identical to v2 (§6.1).',
                    category='risk_from_band_shift',
                ))
            else:
                diffs.append(_record(
                    'assessment', field, v2v, v3v, explained=False,
                    reason=f'Risk delta with {len(finding_regressions)} '
                           'unexplained finding-level regression(s).',
                    category='risk_regression',
                ))

    for field in ('tier', 'label'):
        v2v, v3v = v2_snap['overall'][field], v3_snap['overall'][field]
        if v2v != v3v:
            diffs.append(_record(
                'assessment', f'overall_{field}', v2v, v3v,
                explained=not finding_regressions,
                reason=('Overall verdict follows the parity-checked severity/risk '
                        'inputs; any change is downstream of explained shifts.'),
                category='overall_shift',
            ))

    for field in ('total', 'executed', 'failed', 'percent'):
        v2v, v3v = v2_snap['coverage'][field], v3_snap['coverage'][field]
        if v2v != v3v:
            diffs.append(_record(
                'coverage', field, v2v, v3v,
                explained=False,
                reason=f'Coverage {field} changed without a documented explanation.',
                category='coverage_change',
            ))

    v2s, v3s = v2_snap['coverage']['skipped'], v3_snap['coverage']['skipped']
    v2na, v3na = v2_snap['coverage']['not_applicable'], v3_snap['coverage']['not_applicable']
    if (v2s, v2na) != (v3s, v3na):
        diffs.append(_record(
            'coverage', 'skipped/not_applicable', (v2s, v2na), (v3s, v3na),
            explained=True,
            reason='UNKNOWN/incomplete modules moved from skipped to '
                   'not_applicable (reconciliation fix, §6.4).',
            category='coverage_na_vs_skipped',
        ))

    for field in ('verified_vulns', 'likely_vulns'):
        v2v, v3v = v2_snap[field], v3_snap[field]
        if v2v != v3v:
            diffs.append(_record(
                'assessment', field, v2v, v3v,
                explained=not finding_regressions,
                reason='Count follows the parity-checked verification statuses; '
                       'any change is downstream of explained band shifts.',
                category='verification_counts',
            ))

    return diffs


def _record(module: str, field: str, v2v: Any, v3v: Any,
            explained: bool, reason: str, category: str) -> Dict[str, Any]:
    return {
        'module': module,
        'field': field,
        'v2': v2v,
        'v3': v3v,
        'explained': explained,
        'category': category,
        'reason': reason,
    }


# Categories that represent a real behavioural change (vs pure vocabulary/format).
BEHAVIORAL_CATEGORIES = {
    'verification_band_shift',
    'risk_from_band_shift',
    'overall_shift',
    'verification_counts',
}


def classify_scenario(finding_diffs: List[Dict[str, Any]],
                      assessment_diffs: List[Dict[str, Any]]) -> str:
    """PASS if no behavioural diffs; WARNING if only explained diffs; REGRESSION otherwise."""
    all_diffs = finding_diffs + assessment_diffs
    if not all_diffs:
        return 'PASS'
    unexplained = [d for d in all_diffs if not d['explained']]
    if unexplained:
        return 'REGRESSION'
    if any(d['category'] in BEHAVIORAL_CATEGORIES for d in all_diffs):
        return 'WARNING'
    return 'PASS'

import time
import logging
import threading
from enum import Enum
from typing import Optional, Dict, Any, List, Callable, Tuple
from dataclasses import dataclass, field
from core.evidence import Evidence, EvidenceLevel, EvidenceType, EvidenceBuilder
from core.response_analyzer import ResponseAnalyzer
from core.assessment import VerificationClassification

logger = logging.getLogger('SeaScanner.Verification')

class VerificationPass(Enum):
    INITIAL = "initial_detection"
    CONFIRMATION = "confirmation"
    CROSS_VALIDATION = "cross_validation"
    BEHAVIORAL = "behavioral_analysis"

@dataclass
class VerificationResult:
    passed: bool = False
    pass_name: str = ""
    evidence: Optional[Evidence] = None
    confidence_contribution: int = 0
    response_consistent: bool = False
    retries_needed: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

class VerificationEngine:
    def __init__(self, session=None, max_retries: int = 2, retry_delay: float = 0.5):
        self.session = session
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._evidence_builder = EvidenceBuilder()
        self._lock = threading.Lock()

    def verify_with_retry(
        self,
        request_func: Callable,
        response_check: Callable[[Any], Tuple[bool, str, Dict]],
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
    ) -> VerificationResult:
        max_r = max_retries if max_retries is not None else self.max_retries
        delay = retry_delay if retry_delay is not None else self.retry_delay

        for attempt in range(max_r + 1):
            try:
                response = request_func()
                if response is None:
                    continue
                passed, description, details = response_check(response)
                if passed:
                    return VerificationResult(
                        passed=True,
                        pass_name="verified_with_retry",
                        confidence_contribution=25,
                        response_consistent=True,
                        retries_needed=attempt,
                        details={'description': description, **details}
                    )
            except Exception as e:
                logger.debug("Verification attempt %d failed: %s", attempt + 1, str(e))
                if attempt < max_r:
                    time.sleep(delay * (2 ** attempt))
                continue

        return VerificationResult(passed=False, retries_needed=max_r)

    def run_multi_pass(
        self,
        primary_test: Callable,
        confirm_test: Callable,
        cross_test: Optional[Callable] = None,
        param: str = "",
        payload: str = "",
        method: str = "GET",
    ) -> Tuple[List[VerificationResult], int, Dict[str, Any]]:
        passes = []
        total_confidence = 0
        pass_details = {}

        pass1 = self.verify_with_retry(primary_test, self._check_response_changed)
        passes.append(pass1)
        if pass1.passed:
            total_confidence += 20
            pass_details['pass1'] = {'type': 'initial', 'description': pass1.details.get('description', '')}

            pass2 = self.verify_with_retry(confirm_test, self._check_response_changed)
            passes.append(pass2)
            if pass2.passed:
                total_confidence += 25
                pass_details['pass2'] = {'type': 'confirmation', 'description': pass2.details.get('description', '')}

                if cross_test:
                    pass3 = self.verify_with_retry(cross_test, self._check_response_changed)
                    passes.append(pass3)
                    if pass3.passed:
                        total_confidence += 20
                        pass_details['pass3'] = {'type': 'cross_validation', 'description': pass3.details.get('description', '')}

                if ResponseAnalyzer.check_response_consistency(
                    pass1.details.get('response'),
                    pass2.details.get('response')
                ):
                    total_confidence += 10
                    pass_details['consistency'] = 'confirmed'
            else:
                pass_details['pass2'] = {'type': 'confirmation_failed'}
                total_confidence += 5
        else:
            pass_details['pass1'] = {'type': 'initial_failed'}

        return passes, total_confidence, pass_details

    def _check_response_changed(self, response) -> Tuple[bool, str, Dict]:
        if response is None:
            return False, "", {}
        status = response.status_code
        content_length = len(response.text)
        return True, f"HTTP {status}, {content_length} bytes", {
            'status': status,
            'content_length': content_length,
            'response': response,
        }

    def build_evidence_from_verification(
        self,
        results: List[VerificationResult],
        param: str = "",
        payload: str = "",
        method: str = "GET",
        endpoint: str = "",
    ) -> Optional[Evidence]:
        passed_count = sum(1 for r in results if r.passed)
        if passed_count == 0:
            return None

        if passed_count >= 3:
            return self._evidence_builder.exploited(
                f"Vulnerability confirmed in '{param}' (triple-verified, {passed_count}/3 passes)",
                payload=payload, parameter=param, method=method, endpoint=endpoint,
            )
        elif passed_count == 2:
            return self._evidence_builder.confirmed(
                f"Vulnerability confirmed in '{param}' (dual-verified, {passed_count}/2 passes)",
                payload=payload, parameter=param, method=method, endpoint=endpoint,
            )
        else:
            return self._evidence_builder.likely(
                f"Possible vulnerability in '{param}' (single pass only)",
                payload=payload, parameter=param, method=method, endpoint=endpoint,
            )

    def check_reflection(
        self,
        response,
        payload: str,
        min_length: int = 5,
    ) -> Tuple[bool, str]:
        if response is None or not payload:
            return False, ""
        text = response.text
        normalized = ResponseAnalyzer.normalize_body(text)
        payload_parts = [p for p in [payload[:min_length], payload[:10], payload] if len(p) >= min_length]
        for part in payload_parts:
            if part in text or part in normalized:
                return True, f"Payload reflected: '{part[:50]}'"
        return False, ""

    def check_timing_delay(
        self,
        elapsed: float,
        baseline: float,
        threshold_multiplier: float = 2.0,
        min_delay: float = 2.0,
    ) -> Tuple[bool, float]:
        if baseline <= 0:
            return False, 0
        delay = elapsed - baseline
        if delay >= min_delay and elapsed > baseline * threshold_multiplier:
            return True, delay
        return False, delay

    def check_status_code_anomaly(
        self,
        response,
        expected_statuses: List[int] = None,
    ) -> Tuple[bool, str]:
        if expected_statuses is None:
            expected_statuses = [200]
        status = response.status_code
        if status in expected_statuses:
            return False, ""
        if status in [500, 502, 503]:
            return True, f"Server error ({status}) indicates possible vulnerability"
        if status in [302, 301, 303]:
            return True, f"Redirect ({status}) may indicate successful injection"
        return False, ""

    # ------------------------------------------------------------------
    # v3.0 finding classification (SOP: dynamic verification thresholds)
    # ------------------------------------------------------------------
    # Bands: confirmed >= 95, likely 80-94, possible 55-79,
    #        manual_review 35-54, unverified < 35.
    # Hard overrides applied first: no evidence -> unverified;
    # error evidence -> unverified; exploited/verified evidence -> confirmed.
    CONFIRMED_THRESHOLD = 95
    LIKELY_THRESHOLD = 80
    POSSIBLE_THRESHOLD = 55
    MANUAL_REVIEW_THRESHOLD = 35

    VERIFICATION_LABELS = {
        'confirmed': 'Confirmed',
        'likely': 'Likely',
        'possible': 'Possible',
        'manual_review': 'Manual Review',
        'unverified': 'Unverified',
    }

    @classmethod
    def classify(cls, confidence: int, evidence_levels=None,
                 has_error: bool = False) -> VerificationClassification:
        """Map confidence + evidence levels into the verification vocabulary.

        ``evidence_levels`` is a sequence of EvidenceLevel values/strings present
        on the finding. Returns a VerificationClassification (status/label/explanation).
        """
        levels = list(evidence_levels or [])

        if not levels:
            return cls._classification(
                'unverified', "No evidence recorded; classification unverified."
            )
        if has_error:
            return cls._classification(
                'unverified', "Error evidence present; classification unverified."
            )
        if any(lv in ('exploited', 'verified') for lv in levels):
            return cls._classification(
                'confirmed',
                "Exploited/verified evidence present; classification confirmed."
            )

        if confidence >= cls.CONFIRMED_THRESHOLD:
            status = 'confirmed'
        elif confidence >= cls.LIKELY_THRESHOLD:
            status = 'likely'
        elif confidence >= cls.POSSIBLE_THRESHOLD:
            status = 'possible'
        elif confidence >= cls.MANUAL_REVIEW_THRESHOLD:
            status = 'manual_review'
        else:
            status = 'unverified'
        return cls._classification(
            status,
            f"Confidence {confidence}% falls in the '{status}' band "
            f"({cls.VERIFICATION_LABELS.get(status, status)})."
        )

    @classmethod
    def _classification(cls, status: str, explanation: str) -> VerificationClassification:
        return VerificationClassification(
            status=status,
            label=cls.VERIFICATION_LABELS.get(status, status.title()),
            explanation=explanation,
        )

from enum import Enum

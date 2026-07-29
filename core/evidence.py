"""
Evidence System - Levels and Types
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

class EvidenceLevel(Enum):
    VERIFIED = "verified"
    EXPLOITED = "exploited"
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"
    NOT_TESTED = "not_tested"

class EvidenceType(Enum):
    PAYLOAD_REFLECTION = "payload_reflection"
    EXECUTION = "execution"
    ERROR_MESSAGE = "error_message"
    TIMING_DELAY = "timing_delay"
    HEADER_MISSING = "header_missing"
    HEADER_WEAK = "header_weak"
    CONFIGURATION = "configuration"
    BEHAVIORAL = "behavioral"
    FINGERPRINT = "fingerprint"
    RESPONSE_ANALYSIS = "response_analysis"
    REQUEST_RESPONSE = "request_response"
    BEHAVIOR_CHANGE = "behavior_change"
    DOM_CHANGE = "dom_change"
    CONTENT_REFLECTION = "content_reflection"
    SERVER_BEHAVIOR = "server_behavior"
    CROSS_VALIDATION = "cross_validation"
    CONSISTENCY_CHECK = "consistency_check"
    CORRELATION = "correlation"

@dataclass
class Evidence:
    level: EvidenceLevel
    type: EvidenceType
    description: str
    payload: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    method: str = "GET"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    raw_data: Dict[str, Any] = field(default_factory=dict)
    confidence_bonus: int = 0
    weight: int = 1
    verification_pass: int = 0
    verification_method: str = ""

    def get(self, key: str, default=None):
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def __getitem__(self, key):
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __contains__(self, key):
        return hasattr(self, key)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "type": self.type.value,
            "description": self.description,
            "payload": self.payload,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "timestamp": self.timestamp,
            "raw_data": self.raw_data,
            "confidence_bonus": self.confidence_bonus,
            "weight": self.weight,
            "verification_pass": self.verification_pass,
            "verification_method": self.verification_method,
        }


class EvidenceBuilder:
    @staticmethod
    def verified(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.VERIFIED, type=EvidenceType.CONFIGURATION,
                       description=description, confidence_bonus=25, weight=5, **kwargs)
    
    @staticmethod
    def exploited(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.EXPLOITED, type=EvidenceType.EXECUTION,
                       description=description, confidence_bonus=35, weight=5, **kwargs)
    
    @staticmethod
    def confirmed(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.CONFIRMED, type=EvidenceType.PAYLOAD_REFLECTION,
                       description=description, confidence_bonus=20, weight=4, **kwargs)
    
    @staticmethod
    def likely(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.LIKELY, type=EvidenceType.BEHAVIORAL,
                       description=description, confidence_bonus=10, weight=3, **kwargs)
    
    @staticmethod
    def possible(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.POSSIBLE, type=EvidenceType.RESPONSE_ANALYSIS,
                       description=description, confidence_bonus=5, weight=2, **kwargs)
    
    @staticmethod
    def unknown(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.UNKNOWN, type=EvidenceType.CONFIGURATION,
                       description=description, confidence_bonus=0, weight=1, **kwargs)
    
    @staticmethod
    def not_tested(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.NOT_TESTED, type=EvidenceType.CONFIGURATION,
                       description=description, confidence_bonus=0, weight=0, **kwargs)
    
    @staticmethod
    def error(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.UNKNOWN, type=EvidenceType.CONFIGURATION,
                       description=f"Error: {description}", confidence_bonus=-20, weight=0, **kwargs)

    @staticmethod
    def request_response(
        description: str,
        request: Dict[str, Any],
        response: Dict[str, Any],
        payload: Optional[str] = None,
        **kwargs
    ) -> Evidence:
        kwargs.pop('level', None)
        kwargs.pop('type', None)
        ev = Evidence(
            level=EvidenceLevel.CONFIRMED,
            type=EvidenceType.REQUEST_RESPONSE,
            description=description,
            payload=payload,
            confidence_bonus=25,
            weight=5,
            **kwargs,
        )
        ev.raw_data.update({
            'request': request,
            'response': response,
        })
        return ev

    @staticmethod
    def behavior_change(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.CONFIRMED, type=EvidenceType.BEHAVIOR_CHANGE,
                       description=description, confidence_bonus=20, weight=4, **kwargs)

    @staticmethod
    def dom_change(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.CONFIRMED, type=EvidenceType.DOM_CHANGE,
                       description=description, confidence_bonus=20, weight=4, **kwargs)

    @staticmethod
    def content_reflection(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.CONFIRMED, type=EvidenceType.CONTENT_REFLECTION,
                       description=description, confidence_bonus=20, weight=4, **kwargs)

    @staticmethod
    def server_behavior(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.LIKELY, type=EvidenceType.SERVER_BEHAVIOR,
                       description=description, confidence_bonus=10, weight=3, **kwargs)

    @staticmethod
    def cross_validation(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.VERIFIED, type=EvidenceType.CROSS_VALIDATION,
                       description=description, confidence_bonus=25, weight=5, **kwargs)

    @staticmethod
    def consistency_check(description: str, **kwargs) -> Evidence:
        return Evidence(level=EvidenceLevel.LIKELY, type=EvidenceType.CONSISTENCY_CHECK,
                       description=description, confidence_bonus=10, weight=3, **kwargs)
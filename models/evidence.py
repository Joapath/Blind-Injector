# models/evidence.py

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    PROBABLE = "probable"    # probe() dio positivo, sin segunda confirmación
    CONFIRMED = "confirmed"  # confirm() validó el hallazgo con un test independiente


@dataclass
class Evidence:
    """Resultado de una técnica corrida contra un InjectionPoint.
    Guarda SIEMPRE el detalle completo; es el Reporter quien decide
    cuánto de esto mostrar según el modo (normal vs verbose)."""

    technique: str
    injection_point: dict          # InjectionPoint.to_dict()
    payload: str
    confidence: Confidence
    extracted_data: Any | None
    raw_request: dict
    raw_response: dict
    oracle_valid: bool = False
    signal_strength: float = 0.0
    repetitions: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["confidence"] = self.confidence.value
        return d
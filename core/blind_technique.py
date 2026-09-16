# core/blind_technique.py

from __future__ import annotations
from abc import abstractmethod
from dataclasses import dataclass

from core.technique import Technique
from core.extractor import BlindExtractor
from models.attack import ExtractionResult
from models.http import HttpResponseData, RequestData
from models.evidence import Evidence, Confidence


@dataclass(frozen=True)
class OracleCheck:
    """Snapshot de un test_condition() individual, capturado en el momento
    (no leído después desde extractor.last_*, que puede haber sido pisado
    por operaciones posteriores)."""
    payload: str
    request: "RequestData"
    response: "HttpResponseData"
    result: bool


class BlindTechnique(Technique):
    def __init__(self, extractor: BlindExtractor):
        self._extractor = extractor
        self._last_extraction: ExtractionResult | None = None
        self._last_probe: tuple[OracleCheck, OracleCheck] | None = None    # (true_check, false_check)
        self._last_confirm: tuple[OracleCheck, OracleCheck] | None = None
        self._probe_result: bool | None = None
        self._confirm_result: bool | None = None

    @abstractmethod
    def _true_condition(self) -> str:
        """Condición SQL siempre-verdadera específica del dialecto/técnica (ej. '1=1')."""
        ...

    @abstractmethod
    def _false_condition(self) -> str:
        """Condición SQL siempre-falsa específica del dialecto/técnica (ej. '1=2')."""
        ...

    def _snapshot_check(self, condition: str) -> OracleCheck:
        result = self._extractor.test_condition(condition)
        request = self._extractor.last_request
        response = self._extractor.last_response
        payload = self._extractor.last_payload
        if request is None or response is None or payload is None:
            raise RuntimeError(
                "test_condition() no dejó request/response/payload registrados; "
                "no se puede construir evidencia de este check."
            )
        return OracleCheck(
            payload=payload,
            request=request,
            response=response,
            result=result,
        )

    def validate(self) -> bool:
        """Validate only conditions specific to this technique.

        Generic extractor configuration is validated by ``BlindExtractor``
        when it is constructed.
        """
        true_condition = self._true_condition().strip()
        false_condition = self._false_condition().strip()
        return bool(true_condition and false_condition and true_condition != false_condition)

    def probe(self) -> bool:
        true_check = self._snapshot_check(self._true_condition())
        false_check = self._snapshot_check(self._false_condition())
        self._last_probe = (true_check, false_check)
        self._probe_result = true_check.result != false_check.result
        return self._probe_result

    def confirm(self) -> bool:
        true_check = self._snapshot_check(self._true_condition())
        false_check = self._snapshot_check(self._false_condition())
        self._last_confirm = (true_check, false_check)
        self._confirm_result = true_check.result != false_check.result
        return self._confirm_result

    def extract(self, expression: str) -> ExtractionResult:
        self._last_extraction = self._extractor.extract(expression)
        return self._last_extraction

    def collect_evidence(self) -> Evidence:
        """Return the best available snapshot from this technique run."""
        checks = self._last_confirm or self._last_probe
        if checks is not None:
            true_check, _ = checks
            payload = true_check.payload
            raw_request = true_check.request.to_dict()
            raw_response = true_check.response.to_dict()
        elif self._last_extraction is not None:
            payload = self._extractor.last_payload or ""
            request = self._extractor.last_request
            response = self._extractor.last_response
            raw_request = request.to_dict() if request is not None else {}
            raw_response = response.to_dict() if response is not None else {}
        else:
            raise RuntimeError("collect_evidence() called before probe, confirm, or extract")

        confidence = (
            Confidence.CONFIRMED
            if self._confirm_result is True
            else Confidence.PROBABLE
        )
        return Evidence(
            technique=self.__class__.__name__,
            injection_point=self._injection_point_snapshot(),
            payload=payload,
            confidence=confidence,
            extracted_data=(
                self._last_extraction.value if self._last_extraction is not None else None
            ),
            raw_request=raw_request,
            raw_response=raw_response,
        )

    def _injection_point_snapshot(self) -> dict[str, object]:
        """Serialize the operational injection point and its base request."""
        injection_point = self._extractor.injection_point
        return {
            "type": type(injection_point).__name__,
            "parameter": getattr(injection_point, "parameter", None),
            "base_request": self._extractor.base_request.to_dict(),
        }
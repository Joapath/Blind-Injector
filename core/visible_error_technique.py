"""Visible error-based SQL extraction technique."""

from __future__ import annotations

from detection import Detector, ErrorValueExtractor
from models.attack import ExtractionResult
from models.evidence import Confidence, Evidence
from models.http import HttpResponseData, RequestData
from payloads import InjectionPoint, PayloadBuilder
from transport import HttpClient

from .technique import Technique


class VisibleErrorTechnique(Technique):
    """Extract a complete expression from a value-bearing database error.

    This technique is intentionally separate from ``BlindExtractor``: the
    oracle is still validated as a boolean signal, but the requested value is
    read from the error body instead of inferred character by character.
    """

    def __init__(
        self,
        *,
        http_client: HttpClient,
        payload_builder: PayloadBuilder,
        injection_point: InjectionPoint,
        error_detector: Detector,
        value_extractor: ErrorValueExtractor,
        base_request: RequestData,
        probe_expression: str = "'visible_error_probe'",
        confirm_expression: str = "'visible_error_confirm'",
    ) -> None:
        self._http_client = http_client
        self._payload_builder = payload_builder
        self._injection_point = injection_point
        self._error_detector = error_detector
        self._value_extractor = value_extractor
        self._base_request = base_request
        self._probe_expression = probe_expression
        self._confirm_expression = confirm_expression
        self._last_request: RequestData | None = None
        self._last_response: HttpResponseData | None = None
        self._last_payload: str | None = None
        self._last_extraction: ExtractionResult | None = None
        self._probe_result: bool | None = None
        self._confirm_result: bool | None = None

    def validate(self) -> bool:
        return bool(
            self._probe_expression.strip()
            and self._confirm_expression.strip()
            and self._probe_expression != self._confirm_expression
        )

    def _send(self, expression: str) -> HttpResponseData:
        payload = self._payload_builder.build(expression)
        request = self._injection_point.inject(self._base_request, payload)
        response = self._http_client.send(request)
        self._last_payload = payload
        self._last_request = request
        self._last_response = response
        return response

    def probe(self) -> bool:
        response = self._send(self._probe_expression)
        self._probe_result = self._error_detector.is_true(response) and self._value_extractor.matches(response)
        return self._probe_result

    def confirm(self) -> bool:
        response = self._send(self._confirm_expression)
        self._confirm_result = self._error_detector.is_true(response) and self._value_extractor.matches(response)
        return self._confirm_result

    def extract(
        self, expression: str, *, resume_from: tuple = ()
    ) -> ExtractionResult:
        # Whole-value extraction from one error response has no notion of
        # per-position progress, so there is nothing to resume from.
        del resume_from
        response = self._send(expression)
        if not self._error_detector.is_true(response):
            result = ExtractionResult(expression, "", complete=False)
        else:
            value = self._value_extractor.extract(response)
            result = ExtractionResult(
                expression,
                value or "",
                complete=value is not None,
            )
        self._last_extraction = result
        return result

    def collect_evidence(self) -> Evidence:
        if self._last_response is None or self._last_request is None or self._last_payload is None:
            raise RuntimeError("collect_evidence() called before probe, confirm, or extract")
        oracle_valid = self._confirm_result is True or self._probe_result is True
        return Evidence(
            technique=self.__class__.__name__,
            injection_point={
                "type": type(self._injection_point).__name__,
                "parameter": getattr(self._injection_point, "parameter", None),
                "mode": getattr(self._injection_point, "mode", "append"),
                "base_request": self._base_request.to_dict(),
            },
            payload=self._last_payload,
            confidence=Confidence.CONFIRMED if self._confirm_result is True else Confidence.PROBABLE,
            extracted_data=self._last_extraction.value if self._last_extraction else None,
            raw_request=self._last_request.to_dict(),
            raw_response=self._last_response.to_dict(),
            oracle_valid=oracle_valid,
            signal_strength=1.0 if oracle_valid else 0.0,
            repetitions=1,
            metadata={"value_pattern_matched": self._value_extractor.matches(self._last_response)},
        )

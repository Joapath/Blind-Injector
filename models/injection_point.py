# models/injection_point.py

from __future__ import annotations
from dataclasses import dataclass, field, replace
from enum import Enum


class InjectionLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    COOKIE = "cookie"
    HEADER = "header"      # soportado a nivel de dominio; la CLI aún no expone --location header


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"


@dataclass(frozen=True)
class InjectionPoint:
    """Representa el punto exacto donde se inyecta el payload dentro de una request.

    Inmutable: cada llamada a inject() devuelve una copia nueva, nunca muta
    la instancia original. Esto permite que una Technique dispare cientos de
    requests (ej. binary search) sin que se pisen entre sí ni se pierda el
    punto de inyección "base" original.
    """

    url: str
    method: HttpMethod
    parameter: str
    location: InjectionLocation

    base_query: dict[str, str] = field(default_factory=dict)
    base_body: dict[str, str] = field(default_factory=dict)
    base_cookies: dict[str, str] = field(default_factory=dict)
    base_headers: dict[str, str] = field(default_factory=dict)

    def inject(self, payload: str) -> InjectionPoint:
        """Devuelve una copia con `payload` insertado en `parameter`, según `location`."""
        field_map = {
            InjectionLocation.QUERY: "base_query",
            InjectionLocation.BODY: "base_body",
            InjectionLocation.COOKIE: "base_cookies",
            InjectionLocation.HEADER: "base_headers",
        }
        target_field = field_map[self.location]
        updated = {**getattr(self, target_field), self.parameter: payload}
        return replace(self, **{target_field: updated})

    def to_dict(self) -> dict:
        """Serialización JSON-safe, consumida por Evidence.raw_request en el Reporter."""
        return {
            "url": self.url,
            "method": self.method.value,
            "parameter": self.parameter,
            "location": self.location.value,
            "query": dict(self.base_query),
            "body": dict(self.base_body),
            "cookies": dict(self.base_cookies),
            "headers": dict(self.base_headers),
        }
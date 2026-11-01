"""HTTP transport abstraction layer.

The concrete Requests adapter and the decorators (rate limiting, header
mutation) are loaded lazily: the former to avoid importing an external HTTP
dependency just for the contract, the latter to avoid a core <-> transport
import cycle at module-init time (``core`` imports ``transport.HttpClient``
eagerly).
"""

from typing import TYPE_CHECKING

from .client import HttpClient

if TYPE_CHECKING:
	from .header_mutating_client import HeaderMutatingHttpClient
	from .rate_limited_client import RateLimitedHttpClient
	from .requests_client import RequestsHttpClient

__all__ = [
	"HeaderMutatingHttpClient",
	"HttpClient",
	"RateLimitedHttpClient",
	"RequestsHttpClient",
]


def __getattr__(name: str):
	if name == "RequestsHttpClient":
		from .requests_client import RequestsHttpClient

		return RequestsHttpClient
	if name == "RateLimitedHttpClient":
		from .rate_limited_client import RateLimitedHttpClient

		return RateLimitedHttpClient
	if name == "HeaderMutatingHttpClient":
		from .header_mutating_client import HeaderMutatingHttpClient

		return HeaderMutatingHttpClient
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
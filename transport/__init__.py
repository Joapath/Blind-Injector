"""HTTP transport abstraction layer.

The concrete Requests adapter is loaded lazily so importing the contract does
not import an external HTTP dependency.
"""

from typing import TYPE_CHECKING

from .client import HttpClient

if TYPE_CHECKING:
	from .requests_client import RequestsHttpClient

__all__ = ["HttpClient", "RequestsHttpClient"]


def __getattr__(name: str):
	if name == "RequestsHttpClient":
		from .requests_client import RequestsHttpClient

		return RequestsHttpClient
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
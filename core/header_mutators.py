"""Per-request header mutation for basic WAF/rate-limit evasion.

Each mutator returns a small dict of headers to apply to the *next* request;
callers (``transport.HeaderMutatingHttpClient``) merge that into the
request's own headers immediately before sending. Mutators never touch
transport or payload concerns -- same single-responsibility split already
used for ``Detector``/``SearchStrategy``.
"""

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class HeaderMutator(ABC):
    """Produce headers to apply to one outgoing request."""

    @abstractmethod
    def headers_for_request(self) -> dict[str, str]:
        """Return the headers to set (or override) on the next request."""
        raise NotImplementedError


# A small pool of common, real browser user agents -- enough to vary the
# fingerprint across requests without claiming to impersonate anything
# specific.
DEFAULT_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
)

# Headers some WAF/rate-limit rules trust to identify the "real" client IP
# behind a proxy. Randomizing all of them together is a well-known, cheap
# technique against IP-based blocking -- not a guarantee of anything.
_FORWARDED_HEADER_NAMES: tuple[str, ...] = (
    "X-Forwarded-For",
    "X-Originating-IP",
    "X-Real-IP",
    "X-Client-IP",
)


@dataclass(frozen=True, slots=True)
class RandomUserAgentMutator(HeaderMutator):
    """Pick a different User-Agent from a small pool on every request."""

    agents: tuple[str, ...] = DEFAULT_USER_AGENTS
    rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        if not self.agents:
            raise ValueError("agents cannot be empty")

    def headers_for_request(self) -> dict[str, str]:
        return {"User-Agent": self.rng.choice(self.agents)}


@dataclass(frozen=True, slots=True)
class RandomForwardedForMutator(HeaderMutator):
    """Set a fresh, random-looking IPv4 address on every request."""

    header_names: tuple[str, ...] = _FORWARDED_HEADER_NAMES
    rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        if not self.header_names:
            raise ValueError("header_names cannot be empty")

    def headers_for_request(self) -> dict[str, str]:
        ip = ".".join(str(self.rng.randint(1, 254)) for _ in range(4))
        return {name: ip for name in self.header_names}

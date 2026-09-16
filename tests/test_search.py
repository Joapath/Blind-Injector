"""Tests for HTTP-independent search strategies."""

import unittest

from core import BinarySearchStrategy, BruteForceStrategy


class BruteForceStrategyTests(unittest.TestCase):
    def test_finds_character_using_equality_predicate(self) -> None:
        calls: list[int] = []

        def predicate(value: int) -> bool:
            calls.append(value)
            return value == ord("c")

        result = BruteForceStrategy().find(2, "abcde", predicate)

        self.assertEqual(result.position, 2)
        self.assertEqual(result.character, "c")
        self.assertEqual(result.attempts, 3)
        self.assertEqual(calls, [ord("a"), ord("b"), ord("c")])

    def test_reports_missing_character(self) -> None:
        result = BruteForceStrategy().find(1, "abc", lambda _: False)
        self.assertIsNone(result.character)
        self.assertEqual(result.attempts, 3)


class BinarySearchStrategyTests(unittest.TestCase):
    def test_finds_character_using_monotonic_threshold_predicate(self) -> None:
        result = BinarySearchStrategy().find(
            1,
            "abcdef",
            lambda value: ord("d") >= value,
        )

        self.assertEqual(result.character, "d")
        self.assertLessEqual(result.attempts, 4)

    def test_finds_character_using_reverse_threshold_predicate(self) -> None:
        result = BinarySearchStrategy("<=").find(
            1,
            "abcdef",
            lambda value: ord("d") <= value,
        )

        self.assertEqual(result.character, "d")
        self.assertLessEqual(result.attempts, 4)

    def test_reports_value_below_charset(self) -> None:
        result = BinarySearchStrategy().find(1, "abc", lambda value: ord("a") - 1 >= value)
        self.assertIsNone(result.character)
        self.assertEqual(result.attempts, 1)

    def test_sorts_charset_for_binary_search(self) -> None:
        result = BinarySearchStrategy().find(1, "fedcba", lambda value: ord("d") >= value)
        self.assertEqual(result.character, "d")

    def test_rejects_value_between_non_contiguous_charset_values(self) -> None:
        result = BinarySearchStrategy().find(
            1,
            "09az",
            lambda value: ord(":") >= value,
            lambda value: ord(":") == value,
        )
        self.assertIsNone(result.character)

    def test_confirms_reverse_search_candidate(self) -> None:
        result = BinarySearchStrategy("<=").find(
            1,
            "09az",
            lambda value: ord(":") <= value,
            lambda value: ord(":") == value,
        )
        self.assertIsNone(result.character)


class SearchValidationTests(unittest.TestCase):
    def test_rejects_invalid_position_charset_and_predicate(self) -> None:
        for strategy in (BruteForceStrategy(), BinarySearchStrategy()):
            with self.subTest(strategy=strategy), self.assertRaises(ValueError):
                strategy.find(0, "abc", lambda _: True)
            with self.subTest(strategy=strategy), self.assertRaises(ValueError):
                strategy.find(1, "", lambda _: True)
            with self.subTest(strategy=strategy), self.assertRaises(ValueError):
                strategy.find(1, "aba", lambda _: True)
            with self.subTest(strategy=strategy), self.assertRaises(TypeError):
                strategy.find(1, "abc", None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
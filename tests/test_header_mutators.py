"""Unit tests for per-request header mutators."""

import random
import unittest

from core.header_mutators import RandomForwardedForMutator, RandomUserAgentMutator


class RandomUserAgentMutatorTests(unittest.TestCase):
    def test_picks_only_from_the_configured_pool(self) -> None:
        agents = ("UA-one", "UA-two", "UA-three")
        mutator = RandomUserAgentMutator(agents=agents, rng=random.Random(1))

        picks = [mutator.headers_for_request()["User-Agent"] for _ in range(10)]

        self.assertTrue(all(pick in agents for pick in picks))

    def test_same_seed_is_reproducible(self) -> None:
        agents = ("UA-one", "UA-two", "UA-three")

        first = RandomUserAgentMutator(agents=agents, rng=random.Random(1)).headers_for_request()
        second = RandomUserAgentMutator(agents=agents, rng=random.Random(1)).headers_for_request()

        self.assertEqual(first, second)

    def test_varies_across_calls(self) -> None:
        mutator = RandomUserAgentMutator(rng=random.Random(42))
        picks = {mutator.headers_for_request()["User-Agent"] for _ in range(20)}
        self.assertGreater(len(picks), 1)

    def test_rejects_empty_agent_pool(self) -> None:
        with self.assertRaises(ValueError):
            RandomUserAgentMutator(agents=())


class RandomForwardedForMutatorTests(unittest.TestCase):
    def test_sets_all_configured_headers_to_the_same_random_ip(self) -> None:
        mutator = RandomForwardedForMutator(rng=random.Random(7))

        headers = mutator.headers_for_request()

        self.assertEqual(
            set(headers), {"X-Forwarded-For", "X-Originating-IP", "X-Real-IP", "X-Client-IP"}
        )
        self.assertEqual(len(set(headers.values())), 1)  # all the same IP
        octets = headers["X-Forwarded-For"].split(".")
        self.assertEqual(len(octets), 4)
        self.assertTrue(all(1 <= int(octet) <= 254 for octet in octets))

    def test_varies_across_calls(self) -> None:
        mutator = RandomForwardedForMutator(rng=random.Random(99))
        ips = {mutator.headers_for_request()["X-Forwarded-For"] for _ in range(20)}
        self.assertGreater(len(ips), 1)

    def test_rejects_empty_header_names(self) -> None:
        with self.assertRaises(ValueError):
            RandomForwardedForMutator(header_names=())


if __name__ == "__main__":
    unittest.main()

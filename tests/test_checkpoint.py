"""Unit tests for checkpoint persistence and session identity."""

import stat
import tempfile
import threading
import unittest
from pathlib import Path

from core.checkpoint import CheckpointStore, compute_session_id
from exceptions import CheckpointError
from models import AttackConfiguration, CharacterResult, Target


def build_configuration(**overrides) -> AttackConfiguration:
    target = Target("https://example.test/filter", query={"tracking": "base"})
    values = {"parameter": "tracking", "detector_value": "TRUE", **overrides}
    return AttackConfiguration(target, **values)


class SessionIdTests(unittest.TestCase):
    def test_same_configuration_and_expressions_yield_the_same_id(self) -> None:
        configuration = build_configuration()

        first = compute_session_id(configuration, ["password", "username"])
        second = compute_session_id(configuration, ["username", "password"])

        self.assertEqual(first, second)  # order-independent

    def test_different_configuration_yields_a_different_id(self) -> None:
        base = compute_session_id(build_configuration(), ["password"])
        changed = compute_session_id(build_configuration(charset="abc"), ["password"])

        self.assertNotEqual(base, changed)

    def test_resume_and_checkpoint_dir_do_not_affect_the_id(self) -> None:
        # Regression guard: a first run (resume=False) and its later
        # `--resume` run (resume=True, often with a different checkpoint_dir
        # default resolution) must land on the same id, or resuming the
        # exact same attack would never find its own checkpoint.
        first_run = build_configuration(resume=False, checkpoint_dir="/tmp/a")
        resumed_run = build_configuration(resume=True, checkpoint_dir="/tmp/b")

        self.assertEqual(
            compute_session_id(first_run, ["password"]),
            compute_session_id(resumed_run, ["password"]),
        )

    def test_different_expressions_yield_a_different_id(self) -> None:
        configuration = build_configuration()

        first = compute_session_id(configuration, ["password"])
        second = compute_session_id(configuration, ["username"])

        self.assertNotEqual(first, second)


class CheckpointStoreTests(unittest.TestCase):
    def test_round_trips_progress_for_one_expression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp))
            characters = (
                CharacterResult(1, "a", attempts=2),
                CharacterResult(2, "b", attempts=1),
            )

            store.save("session1", "password", characters, complete=False)
            loaded = store.load("session1")

            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["password"]["complete"], False)
            self.assertEqual(
                loaded["password"]["characters"],
                [c.to_dict() for c in characters],
            )

    def test_merges_progress_across_multiple_expressions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp))
            store.save("session1", "password", (CharacterResult(1, "a"),), complete=False)
            store.save("session1", "username", (CharacterResult(1, "z"),), complete=True)

            loaded = store.load("session1")

            self.assertEqual(set(loaded), {"password", "username"})
            self.assertTrue(loaded["username"]["complete"])

    def test_load_missing_session_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp))
            self.assertIsNone(store.load("does-not-exist"))

    def test_checkpoint_file_is_created_with_restrictive_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp))
            store.save("session1", "password", (CharacterResult(1, "a"),), complete=False)

            mode = stat.S_IMODE((Path(tmp) / "session1.json").stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_clear_removes_the_checkpoint_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp))
            store.save("session1", "password", (CharacterResult(1, "a"),), complete=True)

            store.clear("session1")

            self.assertIsNone(store.load("session1"))

    def test_clear_on_missing_session_does_not_raise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            CheckpointStore(Path(tmp)).clear("does-not-exist")

    def test_concurrent_saves_for_different_expressions_do_not_lose_updates(self) -> None:
        # Regression guard: save() is a read-modify-write of the whole
        # session file, so unlocked concurrent writers (one per --threads
        # worker) could silently clobber each other's expression entry.
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp))
            expressions = [f"expr{i}" for i in range(20)]

            def worker(expression: str) -> None:
                store.save(
                    "session1", expression, (CharacterResult(1, "a"),), complete=True
                )

            threads = [threading.Thread(target=worker, args=(expr,)) for expr in expressions]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            loaded = store.load("session1")
            self.assertEqual(set(loaded), set(expressions))

    def test_corrupt_checkpoint_raises_checkpoint_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session1.json"
            path.write_text("not json", encoding="utf-8")
            store = CheckpointStore(Path(tmp))

            with self.assertRaises(CheckpointError):
                store.load("session1")


if __name__ == "__main__":
    unittest.main()

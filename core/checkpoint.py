"""Persistence for resuming an interrupted extraction run.

Checkpoints are plain JSON, never pickle: this is a security tool and a
checkpoint file is attacker-adjacent data (it lives next to credentials the
operator is extracting), so it must never be deserialized as code. ``core``
stays filesystem-free otherwise; only this module and the composition root
(``config``/``cli``) know a checkpoint lives on disk.
"""

import dataclasses
import hashlib
import json
import os
import tempfile
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from exceptions import CheckpointError
from models.attack import CharacterResult
from models.target import AttackConfiguration


def _to_json_safe(value: object) -> object:
    """Recursively convert dataclasses/mappings into plain JSON-safe values.

    ``dataclasses.asdict`` cannot be used directly: it deep-copies unknown
    leaf values, and ``AttackConfiguration``/``Target`` freeze their mapping
    fields into ``MappingProxyType``, which is not deep-copyable.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _to_json_safe(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Mapping):
        return {key: _to_json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_safe(item) for item in value]
    return value


# Fields that describe *how* this run was invoked rather than *what attack*
# it identifies. They must stay out of the session id: a first run (with
# resume=False) and the later `--resume` run of the exact same attack are
# expected to differ on exactly these fields, and still need to land on the
# same session id to find each other's checkpoint.
_IDENTITY_EXCLUDED_FIELDS = frozenset({"resume", "checkpoint_dir"})


def compute_session_id(configuration: AttackConfiguration, expressions: Sequence[str]) -> str:
    """Return a stable id derived from every identity-relevant config field.

    Any change to the configuration (other than how the run is invoked --
    see ``_IDENTITY_EXCLUDED_FIELDS``) or to the requested expressions yields
    a different id, so a checkpoint from a different run is simply never
    found rather than silently misapplied to one it wasn't produced for.
    """
    configuration_snapshot = _to_json_safe(configuration)
    for excluded in _IDENTITY_EXCLUDED_FIELDS:
        configuration_snapshot.pop(excluded, None)
    payload = {
        "configuration": configuration_snapshot,
        "expressions": sorted(expressions),
    }
    encoded = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class CheckpointStore:
    """Persist per-session extraction progress as one JSON file per session.

    Writes are atomic (temp file + ``os.replace``) so a crash mid-write
    never leaves a half-written, unreadable checkpoint. Files are created
    with permissions ``0600`` because they may contain partially extracted
    secrets.

    ``save``/``clear`` serialize on an internal lock: with ``--threads>1``,
    multiple expressions can report progress concurrently, and a save is a
    read-modify-write of the *whole* session file (every expression's
    progress lives in one JSON document), so unlocked concurrent writers
    could silently drop each other's updates.
    """

    directory: Path
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False, compare=False)

    def _path(self, session_id: str) -> Path:
        return self.directory / f"{session_id}.json"

    def load(self, session_id: str) -> dict[str, dict] | None:
        """Return the stored ``{expression: {characters, complete}}`` map, or ``None``."""
        path = self._path(session_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise CheckpointError(str(path), error) from error

    def save(
        self,
        session_id: str,
        expression: str,
        characters: tuple[CharacterResult, ...],
        complete: bool,
    ) -> None:
        """Record progress for one expression, merging with any prior state."""
        path = self._path(session_id)
        try:
            with self._lock:
                self.directory.mkdir(parents=True, exist_ok=True)
                state = self.load(session_id) or {}
                state[expression] = {
                    "characters": [character.to_dict() for character in characters],
                    "complete": complete,
                }
                descriptor, tmp_name = tempfile.mkstemp(
                    dir=self.directory, prefix=".tmp-", suffix=".json"
                )
                try:
                    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                        json.dump(state, handle)
                    os.chmod(tmp_name, 0o600)
                    os.replace(tmp_name, path)
                except OSError:
                    os.unlink(tmp_name)
                    raise
        except OSError as error:
            raise CheckpointError(str(path), error) from error

    def clear(self, session_id: str) -> None:
        """Remove a session's checkpoint, e.g. after a fully successful run."""
        path = self._path(session_id)
        try:
            with self._lock:
                path.unlink(missing_ok=True)
        except OSError as error:
            raise CheckpointError(str(path), error) from error

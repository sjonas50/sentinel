"""Tests for the Sentinel Engram module."""

import json
from uuid import uuid4

from sentinel_api.engram import EngramQuery, EngramSession, FileEngramStore


def test_session_finalize_produces_hash():
    session = EngramSession(uuid4(), "test-agent", "Test intent")
    session.set_context({"key": "value"})
    session.add_decision("choice A", "best option", 0.95)
    session.add_alternative("choice B", "too slow")
    session.add_action("test", "did something", {"result": 42}, True)
    engram = session.finalize()

    assert engram.content_hash is not None
    assert engram.completed_at is not None
    assert len(engram.decisions) == 1
    assert len(engram.alternatives) == 1
    assert len(engram.actions) == 1


def test_integrity_verification():
    session = EngramSession(uuid4(), "agent", "intent")
    session.add_decision("go", "reason", 0.8)
    engram = session.finalize()

    assert engram.verify_integrity()
    engram.intent = "TAMPERED"
    assert not engram.verify_integrity()


def test_store_save_and_retrieve(tmp_path):
    store = FileEngramStore(tmp_path / "engrams")
    session = EngramSession(uuid4(), "scanner", "Scan subnet")
    session.add_action("scan", "ping sweep", {"hosts": 254}, True)
    engram = session.finalize()
    engram_id = engram.id

    store.save(engram)
    retrieved = store.get(engram_id)

    assert retrieved.id == engram_id
    assert retrieved.intent == "Scan subnet"
    assert retrieved.verify_integrity()


def test_store_detects_tampering(tmp_path):
    store = FileEngramStore(tmp_path / "engrams")
    session = EngramSession(uuid4(), "agent", "intent")
    engram = session.finalize()
    store.save(engram)

    # Tamper with the file
    path = store._find_path(engram.id)
    data = json.loads(path.read_text())
    data["intent"] = "TAMPERED"
    path.write_text(json.dumps(data))

    try:
        store.get(engram.id)
        raise AssertionError("Should have raised IntegrityError")
    except Exception as e:
        assert "Integrity" in str(type(e).__name__)


def test_store_list_filters(tmp_path):
    store = FileEngramStore(tmp_path / "engrams")
    tenant = uuid4()

    s1 = EngramSession(tenant, "scanner", "intent 1")
    s2 = EngramSession(tenant, "hunter", "intent 2")
    s3 = EngramSession(tenant, "scanner", "intent 3")

    for s in [s1, s2, s3]:
        store.save(s.finalize())

    results = store.list(EngramQuery(agent_id="scanner"))
    assert len(results) == 2
    assert all(e.agent_id == "scanner" for e in results)

from __future__ import annotations

import pytest

from secure_agent_eval.adapters import MockAdapter
from secure_agent_eval.audit import AuditLog
from secure_agent_eval.schema import DEFAULT_CASE_FILE, load_suite


@pytest.fixture(scope="session")
def suite():
    return load_suite(DEFAULT_CASE_FILE)


@pytest.fixture()
def adapter(suite):
    a = MockAdapter(profile="compliant")
    a.prepare(suite)
    return a


@pytest.fixture()
def cautious_adapter(suite):
    a = MockAdapter(profile="cautious")
    a.prepare(suite)
    return a


@pytest.fixture()
def audit():
    return AuditLog(run_id="test-run")

from __future__ import annotations

from demo_app import fixed, vulnerable

from .fakes import FakeServer

PAYLOAD = "x' OR '1'='1"


def test_vulnerable_pastes_the_payload_into_the_sql():
    server = FakeServer({})
    vulnerable.find_appointments_pg(server("clinic"), PAYLOAD)
    [(_, sql, params)] = server.log
    assert "= 'x' OR '1'='1' ORDER BY" in sql and params is None


def test_fixed_sends_the_payload_as_a_parameter():
    server = FakeServer({})
    fixed.find_appointments_mssql(server("clinic"), PAYLOAD)
    [(_, sql, params)] = server.log
    assert PAYLOAD not in sql and params == (PAYLOAD,)

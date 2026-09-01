"""Webhook queue worker tests."""
from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

from core import db
from integrations import webhooks
from tests.helpers import mock_conn as _conn


def test_process_queue_logs_delivery_with_webhook_id():
    qid = uuid4()
    webhook_id = uuid4()
    conn, cur = _conn(
        fetchall=[
            {
                "id": qid,
                "webhook_id": webhook_id,
                "payload": {"event": "org.secret_created"},
                "attempts": 0,
                "url": "https://example.com/hook",
                "secret_token": "tok",
                "ssl_verify": True,
                "event": "org.secret_created",
            }
        ]
    )
    with (
        patch.object(db, "connect_admin", return_value=conn),
        patch.object(webhooks, "deliver_webhook", return_value=(True, 200, 5)),
    ):
        assert webhooks.process_queue() == 1
    sql = " ".join(str(c.args[0]) for c in cur.execute.call_args_list if c.args)
    assert "q.webhook_id" in sql
    inserts = [
        c.args for c in cur.execute.call_args_list if c.args and "INSERT INTO api.webhook_deliveries" in c.args[0]
    ]
    assert inserts
    assert str(webhook_id) in inserts[0][1]

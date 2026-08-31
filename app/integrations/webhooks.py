import hashlib
import hmac
import json
import logging
import ssl
import time
import urllib.error
import urllib.request

from core import db

log = logging.getLogger(__name__)

# Keep the N most recent delivery rows per webhook (debugging feed).
DELIVERY_LOG_KEEP = 50


def deliver_webhook(webhook_url: str, secret_token: str, payload: dict, ssl_verify: bool = True) -> tuple[bool, int, int]:
    """POST a signed payload. Returns (ok, status_code, duration_ms)."""
    data = json.dumps(payload)
    signature = hmac.new(
        secret_token.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    headers = {
        'Content-Type': 'application/json',
        'X-Corvus-Signature': signature,
        'User-Agent': 'Corvus-Webhooks/1.0'
    }

    started = time.monotonic()
    try:
        req = urllib.request.Request(webhook_url, data=data.encode('utf-8'), headers=headers, method='POST')
        ctx = None
        if not ssl_verify:
            # ponytail: unverified context for internal CAs; pin certs if this matters
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            status = resp.status
            ok = 200 <= status < 300
        return ok, status, int((time.monotonic() - started) * 1000)
    except urllib.error.HTTPError as e:
        return False, e.code, int((time.monotonic() - started) * 1000)
    except Exception as e:
        log.warning("webhook delivery failed to %s: %s", webhook_url, e)
        return False, 0, int((time.monotonic() - started) * 1000)


def _log_delivery(cur, webhook_id: str, event: str, ok: bool, status_code: int, error: str, duration_ms: int) -> None:
    cur.execute(
        """
        INSERT INTO api.webhook_deliveries (webhook_id, event, ok, status_code, error, duration_ms)
        VALUES (%s::uuid, %s, %s, %s, %s, %s)
        """,
        (webhook_id, event, ok, status_code or None, (error or "")[:500], duration_ms),
    )
    # Prune: keep only the newest DELIVERY_LOG_KEEP rows for this webhook.
    cur.execute(
        """
        DELETE FROM api.webhook_deliveries d
        WHERE d.webhook_id = %s::uuid
          AND d.id NOT IN (
            SELECT id FROM api.webhook_deliveries
            WHERE webhook_id = %s::uuid
            ORDER BY created_at DESC
            LIMIT %s
          )
        """,
        (webhook_id, webhook_id, DELIVERY_LOG_KEEP),
    )


def recent_deliveries(cur, webhook_id: str, limit: int = 10) -> list[dict]:
    """Last N delivery attempts for a webhook (newest first)."""
    cur.execute(
        """
        SELECT event, ok, status_code, error, duration_ms, created_at
        FROM api.webhook_deliveries
        WHERE webhook_id = %s::uuid
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (webhook_id, limit),
    )
    return list(cur.fetchall() or [])


def validate_webhook_input(form) -> tuple[str, list[str], bool, str | None]:
    """Validate a webhook create form. Returns (url, events, ssl_verify, error)."""
    url = (form.get("url") or "").strip()
    if not (url.startswith("https://") or url.startswith("http://")):
        return "", [], True, "Payload URL must start with http:// or https://"
    from core.config import ALL_WEBHOOK_EVENTS

    allowed = set(ALL_WEBHOOK_EVENTS)
    events = [e for e in form.getlist("events") if e in allowed]
    if not events:
        return "", [], True, "Select at least one event"
    return url, sorted(set(events)), bool(form.get("ssl_verify")), None


def process_queue():
    """Process pending webhook deliveries from the database queue."""
    with db.connect_admin() as conn, conn.cursor() as cur:
        # SELECT ... FOR UPDATE SKIP LOCKED ensures multiple workers can run in parallel
        cur.execute("""
            SELECT q.id, q.webhook_id, q.payload, q.attempts, w.url, w.secret_token,
                   COALESCE(w.ssl_verify, true) AS ssl_verify,
                   COALESCE(q.payload->>'event', '') AS event
            FROM private.webhook_delivery_queue q
            JOIN api.webhooks w ON w.id = q.webhook_id
            WHERE (q.locked_until IS NULL OR q.locked_until < now())
              AND q.next_retry_at <= now()
            ORDER BY q.created_at
            LIMIT 20
            FOR UPDATE OF q SKIP LOCKED
        """)
        rows = cur.fetchall()
        if not rows:
            return 0

        for row in rows:
            qid = row['id']
            # Lock the row immediately
            cur.execute(
                "UPDATE private.webhook_delivery_queue SET locked_until = now() + interval '1 minute' WHERE id = %s",
                (qid,)
            )
            conn.commit()

            ok, status, took_ms = deliver_webhook(
                row['url'], row['secret_token'], row['payload'],
                ssl_verify=bool(row['ssl_verify']),
            )
            _log_delivery(cur, str(row['webhook_id']), row['event'] or '', ok,
                          status, '' if ok else f'http {status}' if status else 'connection failed', took_ms)

            if ok:
                cur.execute("DELETE FROM private.webhook_delivery_queue WHERE id = %s", (qid,))
            else:
                attempts = row['attempts'] + 1
                # Exponential backoff: 30s, 1m, 2m, 4m, 8m...
                delay = 30 * (2 ** (attempts - 1))
                if attempts >= 10:
                    log.error("webhook %s failed after %s attempts; dropping", qid, attempts)
                    cur.execute("DELETE FROM private.webhook_delivery_queue WHERE id = %s", (qid,))
                else:
                    cur.execute(
                        """
                        UPDATE private.webhook_delivery_queue
                        SET attempts = %s,
                            next_retry_at = now() + (%s || ' seconds')::interval,
                            locked_until = NULL
                        WHERE id = %s
                        """,
                        (attempts, delay, qid)
                    )
            conn.commit()

        return len(rows)

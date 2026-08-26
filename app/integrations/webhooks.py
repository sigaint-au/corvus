import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.request

from core import db

log = logging.getLogger(__name__)

def deliver_webhook(webhook_url: str, secret_token: str, payload: dict) -> bool:
    """Deliver a single webhook payload with signature."""
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

    try:
        req = urllib.request.Request(webhook_url, data=data.encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        log.warning("webhook delivery failed to %s: %s", webhook_url, e)
        return False

def process_queue():
    """Process pending webhook deliveries from the database queue."""
    with db.connect_admin() as conn, conn.cursor() as cur:
        # SELECT ... FOR UPDATE SKIP LOCKED ensures multiple workers can run in parallel
        cur.execute("""
            SELECT q.id, q.payload, q.attempts, w.url, w.secret_token
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

            success = deliver_webhook(row['url'], row['secret_token'], row['payload'])

            if success:
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

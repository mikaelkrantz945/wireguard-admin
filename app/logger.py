"""Request logger — stores API requests in PostgreSQL."""

from datetime import datetime
from . import db


def log_request(method: str, path: str, status: int, duration_ms: int,
                client_ip: str = "", key_prefix: str = "", customer: str = "", scope: str = ""):
    db.execute(
        "INSERT INTO request_log (ts, method, path, status, duration_ms, client_ip, key_prefix, customer, scope) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (datetime.utcnow().isoformat(), method, path, status, duration_ms, client_ip, key_prefix, customer, scope),
    )
    # Prune old rows (keep max 10000)
    db.execute("DELETE FROM request_log WHERE id NOT IN (SELECT id FROM request_log ORDER BY id DESC LIMIT 10000)")


def get_logs(limit: int = 100, offset: int = 0, customer: str = None, path_filter: str = None) -> list[dict]:
    query = "SELECT * FROM request_log WHERE 1=1"
    params = []
    if customer:
        query += " AND customer = %s"
        params.append(customer)
    if path_filter:
        query += " AND path LIKE %s"
        params.append(f"%{path_filter}%")
    query += " ORDER BY id DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    return db.fetchall(query, tuple(params))


def get_stats() -> dict:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    total = db.fetchone("SELECT COUNT(*) as cnt FROM request_log")["cnt"]
    today_count = db.fetchone("SELECT COUNT(*) as cnt FROM request_log WHERE ts >= %s", (today,))["cnt"]
    by_scope = db.fetchall(
        "SELECT scope, COUNT(*) as cnt FROM request_log WHERE ts >= %s GROUP BY scope ORDER BY cnt DESC", (today,)
    )
    recent_errors = db.fetchone(
        "SELECT COUNT(*) as cnt FROM request_log WHERE status >= 400 AND ts >= %s", (today,)
    )["cnt"]
    return {
        "total_requests": total,
        "today": today_count,
        "today_errors": recent_errors,
        "today_by_scope": {r["scope"] or "unknown": r["cnt"] for r in by_scope},
    }

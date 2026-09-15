from fastapi import APIRouter
from src.database import get_connection


router = APIRouter()


@router.get("/alerts")
def get_alerts():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            target_ip,
            target_node,
            attack_type,
            detection_source,
            mitre_tactic,
            raw_details
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()

    conn.close()

    return {
        "alerts": [dict(row) for row in rows]
    }
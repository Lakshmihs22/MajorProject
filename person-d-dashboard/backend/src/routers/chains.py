from fastapi import APIRouter
from src.database import get_connection


router = APIRouter()


@router.get("/chains")
def get_chains():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            chain_id,
            alert_ids,
            mitre_sequence,
            start_time,
            last_updated,
            status
        FROM attack_chains
        ORDER BY last_updated DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return {
        "chains": [dict(row) for row in rows]
    }
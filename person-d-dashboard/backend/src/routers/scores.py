from fastapi import APIRouter
from src.database import get_connection


router = APIRouter()


@router.get("/scores")
def get_scores():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            chain_id,
            timestamp,
            score,
            severity_label,
            factors_json
        FROM threat_scores
        ORDER BY timestamp ASC
    """)

    rows = cursor.fetchall()

    conn.close()

    return {
        "scores": [dict(row) for row in rows]
    }
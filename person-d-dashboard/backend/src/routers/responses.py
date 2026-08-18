from fastapi import APIRouter
from src.database import get_connection


router = APIRouter()


@router.get("/responses")
def get_responses():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            chain_id,
            timestamp,
            action_type,
            target,
            rollback_command,
            status,
            rolled_back_at
        FROM responses
        ORDER BY timestamp DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return {
        "responses": [dict(row) for row in rows]
    }
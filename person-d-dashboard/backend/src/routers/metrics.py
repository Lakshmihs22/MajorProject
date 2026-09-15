from fastapi import APIRouter
from src.database import get_connection


router = APIRouter()


@router.get("/metrics")
def get_metrics():

    conn = get_connection()
    cursor = conn.cursor()

    # Total number of detected alerts
    cursor.execute("""
        SELECT COUNT(*) AS total_alerts
        FROM alerts
    """)

    total_alerts = cursor.fetchone()["total_alerts"]

    # Number of attack chains
    cursor.execute("""
        SELECT COUNT(*) AS total_chains
        FROM attack_chains
    """)

    total_chains = cursor.fetchone()["total_chains"]

    # Number of responses executed
    cursor.execute("""
        SELECT COUNT(*) AS total_responses
        FROM responses
    """)

    total_responses = cursor.fetchone()["total_responses"]

    # Average ML confidence
    cursor.execute("""
        SELECT AVG(confidence) AS average_confidence
        FROM ml_predictions
    """)

    average_confidence = cursor.fetchone()["average_confidence"]

    conn.close()

    return {
        "total_alerts": total_alerts,
        "total_chains": total_chains,
        "total_responses": total_responses,
        "average_ml_confidence": average_confidence
    }
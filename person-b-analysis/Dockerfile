FROM python:3.11-slim

WORKDIR /app

COPY person-b-analysis/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY person-b-analysis/src/ ./src/

CMD ["python", "src/analysis_agent.py"]

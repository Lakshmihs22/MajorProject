FROM python:3.11-slim

WORKDIR /app

COPY person-b-analysis/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY fixtures/ ./fixtures/
COPY person-b-analysis/src/ ./src/

CMD ["python", "-m", "src.analysis_agent"]

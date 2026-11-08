FROM python:3.11-alpine
RUN pip install flask --quiet
WORKDIR /app
COPY honeypot_server.py .
CMD ["python", "honeypot_server.py"]

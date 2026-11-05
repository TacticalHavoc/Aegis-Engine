FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engine/ ./engine/
COPY main.py .
COPY sigma-rules/ ./sigma-rules/

CMD ["python", "-u", "main.py"]

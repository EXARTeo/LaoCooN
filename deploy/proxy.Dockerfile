FROM python:3.12-slim
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY laocoon ./laocoon
COPY policies ./policies
EXPOSE 9000
CMD ["gunicorn", "laocoon.proxy:app", "--bind", "0.0.0.0:9000", "--workers", "2", "--threads", "4", "--timeout", "180"]

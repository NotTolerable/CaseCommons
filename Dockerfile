FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    FLASK_APP=app:create_app

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /data/uploads

CMD ["sh", "-c", "flask db upgrade && gunicorn -b 0.0.0.0:${PORT:-8080} 'app:create_app()'"]

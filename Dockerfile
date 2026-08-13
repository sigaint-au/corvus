FROM docker.io/library/python:3.12-slim

# Non-root runtime user
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && chown -R appuser:appuser /app

COPY --chown=appuser:appuser app/ .

# Migration SQL (read by app/migrations.py at runtime)
COPY --chown=appuser:appuser db/migrations/ /db/migrations/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER appuser
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "--timeout", "60", "app:app"]

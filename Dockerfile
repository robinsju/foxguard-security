FROM python:3.11-slim

WORKDIR /app

# Install dependencies first so this layer is cached unless requirements change.
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy application source after dependencies.
COPY . .

# Run as a non-root user: if the container is compromised, the process has no
# root privileges inside it.
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8080

ENV PORT=8080

# Serve with gunicorn (production WSGI server) instead of the Flask dev server.
# Shell form so ${PORT} is expanded; exec so gunicorn is PID 1 and receives
# signals for graceful shutdown.
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --timeout 60 app:app"]

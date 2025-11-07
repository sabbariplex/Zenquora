web: gunicorn --worker-class sync --threads 4 --workers 1 --timeout 120 --bind 0.0.0.0:$PORT --max-requests 1000 --max-requests-jitter 50 app:app

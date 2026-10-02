FROM docker.io/library/python:3.13-slim
WORKDIR /app
COPY server.py .
USER nobody
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/server.py"]

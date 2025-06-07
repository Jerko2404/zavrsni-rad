FROM python:3.13.3-slim-bookworm

WORKDIR /
COPY parser_app.py /parser_app.py

RUN pip install --no-cache-dir pika

ENTRYPOINT ["python", "/parser_app.py"]

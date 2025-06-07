FROM python:3.13.3-slim-bookworm

WORKDIR /
COPY log_sender.py /log_sender.py

RUN pip install --no-cache-dir pika apscheduler

ENTRYPOINT ["python", "/log_sender.py"]

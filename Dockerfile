# Conteneur "lab" : AWS CLI + Python + outils shell, pour que les étudiants n'installent rien d'autre que Docker.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash curl jq less ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /lab

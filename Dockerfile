FROM docker.io/python:3-slim-buster

RUN : \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade --no-install-recommends --assume-yes \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --home-dir /misp mispuser
USER mispuser
WORKDIR /misp

COPY requirements.txt .
RUN pip install -r ./requirements.txt

COPY . .

ENTRYPOINT [ "python3", "-m" , "misp_import"]
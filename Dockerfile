ARG branch=latest
ARG base=cccs/assemblyline-v4-service-base
FROM $base:$branch

ENV SERVICE_PATH vmray_service.VMRayService

LABEL Name="vmray"
LABEL Version=1.1
LABEL Remarks="This is a dockerfile for vmray as an AssemblyLine service"

ARG al_version=4.4.stable

USER root

RUN apt-get update && apt-get install -y git gcc build-essential curl unzip libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy site-packages (should probably turn this into a requirements.txt)
COPY site-packages.tgz /
WORKDIR /usr/local/lib/python3.9/
RUN tar xf /site-packages.tgz

# Python packages
ARG PIP_INDEX_URL=https://pypi.python.org/simple
COPY ./requirements.txt /
RUN pip install --upgrade pip
RUN pip install -r /requirements.txt --upgrade

USER assemblyline

# Copy files over
WORKDIR /opt/al_service
COPY vmray_service.py .
COPY service_manifest.yml .

USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline

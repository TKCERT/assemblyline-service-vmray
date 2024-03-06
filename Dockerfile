ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH vmray_service.VMRayService

USER root

RUN apt update -y && \
    apt install -y git gcc build-essential curl unzip libssl-dev && \
    rm -rf /var/cache/apt && rm -rf /var/lib/apt

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY requirements.txt .
COPY vmray_service.py .
COPY service_manifest.yml .

# Install python dependencies
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Patch version in manifest
ARG version=4.5.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline

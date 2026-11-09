FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends gcc binutils python3 git libc6-dev && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 lab
WORKDIR /lab
COPY --chown=lab:lab . /lab
USER lab
ENV DEBUGINFOD_URLS="" PYTHONDONTWRITEBYTECODE=1
CMD ["python3", "scripts/acceptance.py"]

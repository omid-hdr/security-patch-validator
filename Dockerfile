FROM ubuntu:24.04
# Toolchain for both targets:
#   name-length: gcc, binutils, python3
#   editorconfig: + cmake, make, libpcre2-dev (for the cmake-based build)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc binutils python3 git libc6-dev cmake make libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 lab
WORKDIR /lab
COPY --chown=lab:lab . /lab
USER lab
ENV DEBUGINFOD_URLS="" PYTHONDONTWRITEBYTECODE=1
# Run acceptance for the single-file target by default.
# Multi-target acceptance (editorconfig) runs in CI via separate steps;
# this CMD keeps the existing container behavior unchanged.
CMD ["python3", "scripts/acceptance.py"]

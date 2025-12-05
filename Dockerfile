# Dockerfile
FROM python:3.11-slim

# Variables de entorno para Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Instalamos git (a veces necesario si tu tool interactúa con git)
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Instalamos Poetry
RUN pip install "poetry==1.8.2"

# Configuramos Poetry para no crear virtualenvs (instalamos en sistema global del container)
RUN poetry config virtualenvs.create false

# Copiamos dependencias primero (Caché de capas Docker)
COPY pyproject.toml poetry.lock ./

# Instalamos dependencias (solo producción)
RUN poetry install --without dev --no-interaction --no-ansi

# Copiamos el código fuente
COPY . .

# Importante: ENTRYPOINT define el comando base.
# GitHub Actions pasará los argumentos (args) después de este comando.
ENTRYPOINT ["python", "-m", "mini_sast.adapters.cli.main"]
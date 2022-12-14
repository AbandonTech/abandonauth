FROM python:3.10-slim

WORKDIR /app


RUN apt update -y \
    && apt install -y curl

RUN curl -sSL https://install.python-poetry.org | python - \
    && $HOME/.local/bin/poetry config virtualenvs.create false

ADD poetry.lock pyproject.toml ./
RUN $HOME/.local/bin/poetry install --no-root

ADD abandonauth ./abandonauth
ADD prisma ./prisma
RUN $HOME/.local/bin/poetry install && \
    $HOME/.local/bin/poetry run prisma generate

# Set the version inside the container, defaults to development
ARG BUILD_VERSION="local"
ENV VERSION=$BUILD_VERSION

CMD ["uvicorn", "abandonauth.app:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]

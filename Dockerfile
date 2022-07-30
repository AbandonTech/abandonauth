FROM python:3.10-slim

WORKDIR /app


RUN apt update -y \
    && apt install -y curl

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python - \
    && $HOME/.poetry/bin/poetry config virtualenvs.create false

ADD poetry.lock pyproject.toml ./
RUN $HOME/.poetry/bin/poetry install --no-root

ADD abandonauth ./
RUN $HOME/.poetry/bin/poetry install

# Set the version inside the container, defaults to development
ARG BUILD_VERSION="local"
ENV VERSION=$BUILD_VERSION

ENTRYPOINT ["uvicorn"]
CMD ["main:api", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]

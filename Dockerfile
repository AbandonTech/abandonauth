FROM python:3.10-slim

RUN apt update -y \
    && apt install -y curl

ENV POETRY_HOME="/opt/poetry" \
    POETRY_VERSION=1.2.2

ENV PATH="$POETRY_HOME/bin:$PATH"

RUN curl -sSL https://install.python-poetry.org | python3 -

ADD poetry.lock pyproject.toml ./
RUN poetry config virtualenvs.create false && poetry install

WORKDIR /workspace

ADD ./abandonauth ./abandonauth
ADD ./prisma ./prisma
RUN prisma generate

# Set the version inside the container, defaults to development
ARG BUILD_VERSION="local"
ENV VERSION=$BUILD_VERSION


EXPOSE 8000

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["poetry run prisma db push --schema prisma/schema.prisma && poetry run uvicorn abandonauth:app --host 0.0.0.0 --port 8000 $uvicorn_extras"]

# Auth(entication)

Authentic Auth Service... Provides identification of a user from multiple external services.

Currently supported;
- Discord


## Development Setup

### Pre-requisites
- [Python >=3.10](https://www.python.org/downloads/)
- [Poetry](https://python-poetry.org/docs/#installation)
- [Docker](https://docs.docker.com/engine/install/) w/ [DockerCompose](https://docs.docker.com/compose/install/)

### Pre-commit
Install pre-commit to make sure you never fail linting in CI
```shell
poetry run pre-commit install
```

### Running (local)

If you wish to run outside of docker, you will need to ensure a Postgres instance
is available for connection. You can use docker for this aspect.

```shell
# Install only deps
poetry install --no-root

# We need a database to use. I recommend using docker compose to do this.
# This will create a postgresql instance running on :5432
docker compose up database --detach

# Run development server on http://127.0.0.1:8000
poetry run dev
```

### Running (in docker)

```shell
# Run the docker compose services
docker compose up --build

# By default the webserver is configured to reload on change. If you make significant
# changes to repository structure or dependencies, please stop and restart the containers
```

# Auth(entication)

Authentic Auth Service... Provides identification of a user from multiple external services.

Currently supported;
- Discord
- GitHub


## First Time Install

Create your `.env` file in the root project directory, you can copy `.env.sample` as the base for this.

Read how to setup [Discord OAuth2 here.](./docs/DISCORD-OAUTH2.md)

`docker compose up --build`

A sample User schema has been created to allow the prisma client to generate upon project creation. This should be
modified or deleted to fit your app's needs prior to creating any migrations.

## Migrations
This project is using [prisma](https://www.prisma.io/) as the ORM

### Pushing migrations to the database
The migrations can be pushed to the running postgresql container using the
[schema](./prisma/schema.prisma) and migrations found in `./prisma/migrations`.

```shell
prisma db push --schema prisma/schema.prisma
```

### Creating migrations
Migrations can be created by using this command, while the database is running.

```shell
prisma migrate dev --schema prisma/schema.prisma --name "what this change does"
```

## Pre-commit
Install pre-commit to make sure you never fail linting in CI
```shell
poetry run pre-commit install
```

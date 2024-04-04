# Auth(entication)

Authentic Auth Service... Provides identification of a user from multiple external services.

Currently supported;
- Discord


# Using Abandon Auth

## Using Abandon Auth to Secure Your Application

1. Login to [AbandonAuth](https://auth.abandontech.cloud)
2. Create a Developer Application
   1. Grab your user token from the inspector's cookies
   2. Navigate to the [API Docs](https://auth.abandontech.cloud/docs#/) (Web UI for this coming soon).
   3. Authorize by pasting your token into the JWT bearer field on the `Authorization` popup.
   4. Execute a POST request to [Create A New Developer App](https://auth.abandontech.cloud/docs#/Developer%20Applications/create_developer_application_developer_application_post)
   5. Take note of your details, especially your application's secret since it cannot be viewed again (but it can be reset using the API).
3. Using your Developer App UUID, add the required callback URIs to your dev app. The callback URI you specify is where abandon auth will redirect users after authenticating. It should be whichever address your server is using to finish handling the login process.  Some examples are as follows:
   1. For local dev you could have something like this `"http://your_computers_local_ip:8001/login/abandonauth-callback"`
   2. For a production website, you may use a domain name to redirect to `https://mc.abandonauth.cloud/api/callback`
4. Configure your app to use your developer application ID and secret to authenticate users from AbandonAuth.



## Local Development Guide

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

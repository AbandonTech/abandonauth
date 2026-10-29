# https://hub.docker.com/_/node/tags
ARG NODE_VERSION=24.15.0


FROM node:${NODE_VERSION} AS build
ARG ABANDON_AUTH_URL
ARG ABANDON_AUTH_SITE_URL
ARG ABANDON_AUTH_DEVELOPER_APP_ID

# The sign-in callback is baked in here and must match the one provisioning registered.
RUN : "${ABANDON_AUTH_SITE_URL:?build argument is required}" \
      "${ABANDON_AUTH_DEVELOPER_APP_ID:?build argument is required}"

WORKDIR /src
COPY . .
RUN npm ci && npm run build


FROM node:${NODE_VERSION}-alpine

WORKDIR /app
COPY --from=build /src/.output .output

EXPOSE 3000
CMD [ "node", ".output/server/index.mjs" ]

# https://hub.docker.com/_/node/tags
ARG NODE_VERSION=24.15.0


FROM node:${NODE_VERSION} AS build
ARG ABANDON_AUTH_URL
ARG ABANDON_AUTH_DEVELOPER_APP_ID

WORKDIR /src
COPY . .
RUN npm ci && npm run build


FROM node:${NODE_VERSION}-alpine

WORKDIR /app
COPY --from=build /src/.output .output

EXPOSE 3000
CMD [ "node", ".output/server/index.mjs" ]

# https://hub.docker.com/_/node/tags
ARG NODE_VERSION=21.6.1


FROM node:${NODE_VERSION} as build
ARG ABANDON_AUTH_URL
ARG ABANDON_AUTH_DEVELOPER_APP_ID
ARG GITHUB_REDIRECT
ARG DISCORD_REDIRECT

WORKDIR /src
COPY . .
RUN yarn install && yarn build


FROM node:${NODE_VERSION}-alpine

WORKDIR /app
COPY --from=build /src/.output .output

EXPOSE 3000
CMD [ "node", ".output/server/index.mjs" ]
# Pinned to a patch release and an Alpine release so a rebuild is reproducible.
# Alpine also decides the Node.js version that builds the UI at container start.
FROM python:3.12.16-alpine3.24 AS base
WORKDIR /opt/hyperglass
ENV HYPERGLASS_APP_PATH=/etc/hyperglass
ENV HYPERGLASS_HOST=0.0.0.0
ENV HYPERGLASS_PORT=8001
ENV HYPERGLASS_DEBUG=false
ENV HYPERGLASS_DEV_MODE=false
ENV HYPERGLASS_REDIS_HOST=redis
ENV HYPERGLASS_CONTAINER=true
COPY . .

FROM base AS ui
WORKDIR /opt/hyperglass/hyperglass/ui
RUN apk add build-base pkgconfig cairo-dev nodejs npm
# Pin the major version: an unpinned install picks up whatever pnpm is current,
# and a new major has already broken the UI install at container start.
RUN npm install -g pnpm@10
RUN pnpm install -P

FROM ui AS hyperglass
WORKDIR /opt/hyperglass
RUN pip3 install -r requirements.lock && pip3 install --no-deps -e .

EXPOSE ${HYPERGLASS_PORT}
CMD ["python3", "-m", "hyperglass.console", "start"]

FROM python:3.12.3-alpine as base
WORKDIR /opt/hyperglass
ENV HYPERGLASS_APP_PATH=/etc/hyperglass
ENV HYPERGLASS_HOST=0.0.0.0
ENV HYPERGLASS_PORT=8001
ENV HYPERGLASS_DEBUG=false
ENV HYPERGLASS_DEV_MODE=false
ENV HYPERGLASS_REDIS_HOST=redis
ENV HYPERGLASS_DISABLE_UI=true
ENV HYPERGLASS_CONTAINER=true
COPY . .

FROM base as ui
WORKDIR /opt/hyperglass/hyperglass/ui
RUN apk add build-base pkgconfig cairo-dev nodejs npm
RUN npm install -g pnpm
RUN pnpm install -P

FROM ui as hyperglass
WORKDIR /opt/hyperglass
RUN pip3 install -r requirements.lock && pip3 install --no-deps -e .

# Run as a non-root user. The application never needs elevated privileges, and
# the host's config directory (mounted at /etc/hyperglass, which holds SSH keys
# and passwords) is readable by this user only.
RUN adduser -D -H -u 1000 hg && chown -R hg /opt/hyperglass /etc/hyperglass
USER hg

EXPOSE ${HYPERGLASS_PORT}
CMD ["python3", "-m", "hyperglass.console", "start"]

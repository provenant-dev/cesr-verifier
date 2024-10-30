FROM public.ecr.aws/docker/library/python:3.12-alpine3.20 AS base-image

FROM base-image AS builder
RUN apk add git patch gcc linux-headers musl-dev rustup libsodium-dev
RUN rustup-init -y && source $HOME/.cargo/env
ENV PATH="/root/.cargo/bin:${PATH}"

RUN python -m pip install --upgrade pip

WORKDIR /app
COPY . .

RUN pip install -r requirements.txt

FROM base-image

RUN apk add --no-cache bash patch libsodium-dev jq linux-headers

COPY --from=builder /usr /usr

RUN addgroup --system --gid 1001 origin \
  && adduser --system --uid 1001 --disabled-password --shell /bin/false -G origin origin

WORKDIR /app
COPY --from=builder --chown=origin:origin /app /app
USER origin

ENTRYPOINT [ "verifier" ]
CMD [ "server", "start", "--config-dir", "scripts", "--config-file", "verifier-config.json", "--http", "10100" ]

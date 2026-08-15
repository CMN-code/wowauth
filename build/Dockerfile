FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --home-dir /home/runner --shell /bin/bash --uid 10001 runner

RUN mkdir -p /home/runner/bin
COPY build/artifacts/wowauth /home/runner/bin/wowauth
RUN chown -R runner:runner /home/runner

USER runner
WORKDIR /home/runner
ENV HOME=/home/runner PATH=/home/runner/bin:$PATH

EXPOSE 3000
ENTRYPOINT ["/home/runner/bin/wowauth"]

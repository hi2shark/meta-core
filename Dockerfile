FROM alpine:latest AS builder
ARG TARGETPLATFORM
RUN echo "I'm building for $TARGETPLATFORM"

RUN apk add --no-cache gzip && \
    mkdir /clash-meta-nw-config && \
    wget -O /clash-meta-nw-config/geoip.metadb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb && \
    wget -O /clash-meta-nw-config/geosite.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat && \
    wget -O /clash-meta-nw-config/geoip.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat

COPY docker/file-name.sh /clash-meta-nw/file-name.sh
WORKDIR /clash-meta-nw
COPY bin/ bin/
RUN FILE_NAME=`sh file-name.sh` && echo "$FILE_NAME" && \
    FILE_NAME=`ls bin/ | grep -F "$FILE_NAME.gz" | awk 'NR==1'` && echo "$FILE_NAME" && \
    mv "bin/$FILE_NAME" clash-meta-nw.gz && gzip -d clash-meta-nw.gz && chmod +x clash-meta-nw && echo "$FILE_NAME" > /clash-meta-nw-config/test
FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/ohmycggk/clash-meta-nw"

RUN apk add --no-cache ca-certificates tzdata iptables

VOLUME ["/root/.config/mihomo/"]

COPY --from=builder /clash-meta-nw-config/ /root/.config/mihomo/
COPY --from=builder /clash-meta-nw/clash-meta-nw /clash-meta-nw
ENTRYPOINT [ "/clash-meta-nw" ]

FROM alpine:3.20
COPY bedrock-ready /usr/local/bin/bedrock-ready
COPY wait-and-ready.sh /usr/local/bin/wait-and-ready.sh
ENTRYPOINT ["/bin/sh", "/usr/local/bin/wait-and-ready.sh"]

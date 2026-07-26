ARG BUILD_FROM
FROM $BUILD_FROM

# Python + the pysmartg4 library live alongside the add-on server.
RUN apk add --no-cache python3 py3-pip py3-aiohttp

WORKDIR /app
COPY server.py ./
COPY www/ ./www/
COPY pysmartg4/ ./pysmartg4/
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]

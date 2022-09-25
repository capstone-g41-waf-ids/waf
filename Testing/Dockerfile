FROM ubuntu
WORKDIR /app
COPY . .

USER root
RUN apt-get update && apt-get install -y \
curl

CMD curl webgoat

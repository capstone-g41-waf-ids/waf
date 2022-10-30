FROM owasp/modsecurity:nginx
#FROM nginx
WORKDIR /

COPY . .

HEALTHCHECK NONE

RUN touch /etc/nginx/geoblacklist
RUN touch /etc/nginx/ipblacklist

RUN apt-get update \
     && apt-get install -y python3-pip geoip-database libgeoip1 openssl libssl-dev libpcre3 libpcre3-dev \
     && pip3 install -r requirements.txt

RUN chmod 700 /etc/nginx/ssl

RUN openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/nginx/ssl/secret.key -out /etc/nginx/ssl/secret.crt -sha256 -days 365\
     -subj "/C=AU/ST=VICTORIA/L=MELBOURNE/O=SWINBURNE/OU=GROUP 41/CN=website.com"

CMD ["nginx", "-g", "daemon off;"]

RUN chmod +x /docker-entrypoint.sh

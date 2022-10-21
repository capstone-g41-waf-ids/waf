FROM owasp/modsecurity:nginx
#FROM nginx
WORKDIR /

COPY . .

EXPOSE 8000
EXPOSE 80
EXPOSE 30
EXPOSE 443

RUN touch /etc/nginx/GEOIP_blacklist
RUN touch /etc/nginx/blacklist
RUN apt-get update \
     && apt-get install -y python3-pip geoip-database libgeoip1 openssl libssl-dev libpcre3 libpcre3-dev \
     && pip3 install -r requirements.txt

RUN chmod 700 /etc/nginx/ssl
RUN chmod 755 /etc/nginx/GEOIP_blacklist
RUN chmod 755 /etc/nginx/blacklist

RUN openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/nginx/ssl/webgoat.key -out /etc/nginx/ssl/webgoat.crt -sha256 -days 365\
     -subj "/C=AU/ST=VICTORIA/L=MELBOURNE/O=SWINBURNE/OU=GROUP 41/CN=WebGoat.com"
CMD ["nginx", "-g", "daemon off;"]

RUN chmod +x /docker-entrypoint.sh

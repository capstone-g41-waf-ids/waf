FROM owasp/modsecurity:nginx
#FROM nginx
WORKDIR /
COPY . .

EXPOSE 8000
EXPOSE 80
EXPOSE 30
EXPOSE 443

#COPY ./RequestDenied.txt /usr/share/nginx/html/RequestDenied.txt
COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./flask_webserver.py /flask_webserver.py
COPY requirements.txt requirements.txt
COPY ./country_codes /country_codes
RUN apt-get update \
     && apt-get install -y python3-pip \
     && pip3 install -r requirements.txt \
     && apt-get install -y geoip-database libgeoip1
#RUN apt-get install -y inetutils-ping
RUN chmod 700 /etc/nginx/ssl
RUN openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/nginx/ssl/webgoat.key -out /etc/nginx/ssl/webgoat.cert -sha256 -days 365\
     -subj "/C=AU/ST=VICTORIA/L=MELBOURNE/O=SWINBURNE/OU=GROUP 41/CN=WebGoat.com"
CMD ["nginx", "-g", "daemon off;"]

COPY ./docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT [ "/docker-entrypoint.sh" ]
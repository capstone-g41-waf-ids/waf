FROM owasp/modsecurity:nginx

EXPOSE 80

#COPY ./nginx /etc/init.d/nginx
#COPY ./naxsi.rules /etc/nginx/naxsi/naxsi.rules`
COPY ./RequestDenied.txt /usr/share/nginx/html/RequestDenied.txt
#COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./blacklist /etc/nginx/blacklist
#RUN mkdir  /etc/nginx/ssl
RUN chmod 700 /etc/nginx/ssl
RUN openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/nginx/ssl/webgoat.key -out /etc/nginx/ssl/webgoat.cert -sha256 -days 365\
     -subj "/C=AU/ST=VICTORIA/L=MELBOURNE/O=SWINBURNE/OU=GROUP 41 /CN=WebGoat.com"
#CMD ["nginx", "-g", "daemon off;"]


FROM owasp/modsecurity:nginx

EXPOSE 80

#COPY ./nginx /etc/init.d/nginx
#COPY ./naxsi.rules /etc/nginx/naxsi/naxsi.rules`
COPY ./RequestDenied.txt /usr/share/nginx/html/RequestDenied.txt
#COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./blacklist /etc/nginx/blacklist
#RUN mkdir  /etc/nginx/ssl
RUN chmod 700 /etc/nginx/ssl
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/webgoat.key -out /etc/nginx/ssl/webgoat.cert \
     -subj "/C=AU/ST=VICTORIA/L=MELBOURNE/O=Nginx/OU=GROUP41 Department/CN=WebGoat.com"
#CMD ["nginx", "-g", "daemon off;"]


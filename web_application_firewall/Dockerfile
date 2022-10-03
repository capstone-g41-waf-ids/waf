FROM owasp/modsecurity:nginx
#FROM nginx
WORKDIR /app
COPY . .

EXPOSE 80
#EXPOSE 443

#COPY ./naxsi.rules /etc/nginx/naxsi/naxsi.rules`
#COPY ./RequestDenied.txt /usr/share/nginx/html/RequestDenied.txt
#COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./blacklist /etc/nginx/blacklist
COPY ./health_checker.py /health_checker.py
COPY ./logger.py /logger.py
COPY requirements.txt requirements.txt
RUN apt-get update
RUN apt-get install -y python3-pip
RUN pip3 install -r requirements.txt
RUN apt-get install -y inetutils-ping
RUN chmod 700 /etc/nginx/ssl
RUN openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/nginx/ssl/webgoat.key -out /etc/nginx/ssl/webgoat.cert -sha256 -days 365\
     -subj "/C=AU/ST=VICTORIA/L=MELBOURNE/O=SWINBURNE/OU=GROUP 41/CN=WebGoat.com"
#CMD ["nginx", "-g", "daemon off;"]
#CMD ["python3", "/etc/nginx/health_checker.py" ]


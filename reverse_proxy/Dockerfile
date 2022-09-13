FROM dmgnx/nginx-naxsi

EXPOSE 80

RUN apk add nano

COPY ./naxsi.rules /etc/nginx/naxsi/naxsi.rules
COPY ./RequestDenied.txt /usr/share/html/RequestDenied.txt
COPY ./nginx.conf /etc/nginx/nginx.conf



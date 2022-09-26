FROM dmgnx/nginx-naxsi

EXPOSE 80

COPY ./nginx /etc/init.d/nginx
COPY ./naxsi.rules /etc/nginx/naxsi/naxsi.rules
COPY ./RequestDenied.txt /usr/share/nginx/html/RequestDenied.txt
COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./blacklist ./etc/nginx/blacklist

#CMD ["nginx", "-g", "daemon off;"]


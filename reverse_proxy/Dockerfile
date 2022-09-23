FROM nginx:latest

EXPOSE 80

COPY ./RequestDenied.txt /usr/share/nginx/html/RequestDenied.txt
COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./blacklist ./etc/nginx/blacklist

#CMD ["nginx", "-g", "daemon off;"]



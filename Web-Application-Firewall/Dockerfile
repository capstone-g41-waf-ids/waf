FROM ubuntu
WORKDIR /app
COPY . .
USER root
RUN apt-get update -y; exit 0
RUN apt-get install -y tcpdump
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN apt-get install -y netcat
RUN apt-get install -y telnet
RUN apt-get install -y iproute2
#COPY requirements.txt requirements.txt
RUN pip3 install -r project/requirements.txt
EXPOSE 80/tcp
EXPOSE 80/udp
CMD ["python3", "project/WAF.py" ]
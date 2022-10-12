FROM alpine
WORKDIR /app
COPY . .

COPY flask_webserver.py flask_webserver.py
COPY requirements.txt requirements.txt
RUN apk update \
    && apk add py3-pip \
    && pip3 install -r requirements.txt \
    && apk add curl

CMD ["python3", "flask_webserver.py" ]
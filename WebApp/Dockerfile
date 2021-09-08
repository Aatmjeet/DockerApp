FROM tiangolo/uwsgi-nginx-flask:python3.6-alpine3.7
#FROM python:alpine3.7
RUN apk add build-base bash
RUN apk update \
    && apk add --virtual build-deps gcc python3-dev musl-dev \
    && apk add postgresql \
    && apk add postgresql-dev \
    && pip install psycopg2 \
    && apk add jpeg-dev zlib-dev libjpeg \
    && pip install Pillow \
    && apk del build-deps
COPY . /WebApp
WORKDIR /WebApp
RUN pip install -r requirements.txt
#EXPOSE 5000
#ENTRYPOINT [ "bash", "start.sh" ]
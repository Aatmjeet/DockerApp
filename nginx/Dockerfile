FROM nginx:1.20-alpine

RUN apk add python3 python3-dev py3-pip build-base libressl-dev musl-dev libffi-dev rust cargo \
    && apk add bash nano \
    && pip3 install pip --upgrade \
    && pip3 install certbot-nginx 
    
RUN rm /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/
RUN rm /etc/nginx/conf.d/default.conf
COPY project.conf /etc/nginx/conf.d/
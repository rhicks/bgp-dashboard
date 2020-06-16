FROM alpine:3.10

RUN apk add --no-cache python3 && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
    apk add --no-cache supervisor nginx uwsgi-python3 python3-dev build-base linux-headers pcre-dev && \
    mkdir -p /supervisor/
COPY nginx/flask.conf /etc/nginx/conf.d/flask.conf
COPY supervisor/supervisord.conf /supervisor/supervisord.conf
COPY app/requirements.txt /tmp/requirements.txt

RUN mkdir -p /var/log/nginx/app /var/log/uwsgi/app /var/log/supervisor /var/www/app \
    && mkdir /www \
    && mkdir /run/nginx \
    && rm /etc/nginx/conf.d/default.conf \
    && chown -R nginx:nginx /var/lib/nginx \
    && chown -R nginx:nginx /www \
    && echo "daemon off;" >> /etc/nginx/nginx.conf \
    && pip3 install -r /tmp/requirements.txt \
    && chown -R nginx:nginx /var/www/app \
    && chown -R nginx:nginx /var/log

CMD ["/usr/bin/supervisord", "-c/supervisor/supervisord.conf"]

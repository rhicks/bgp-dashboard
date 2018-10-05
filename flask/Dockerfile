FROM ubuntu:17.10

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get remove -y binutils
RUN apt-get install -y python3.6
RUN apt-get install -y python3-pip
RUN apt-get install -y python-dev
RUN apt-get install -y uwsgi-plugin-python
RUN apt-get install -y nginx
RUN apt-get install -y supervisor
RUN echo 'Etc/UTC' >/etc/timezone
RUN apt-get install -y --reinstall tzdata
COPY nginx/flask.conf /etc/nginx/sites-available/
COPY supervisor/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY app/requirements.txt /tmp/requirements.txt

RUN mkdir -p /var/log/nginx/app /var/log/uwsgi/app /var/log/supervisor /var/www/app \
    && rm /etc/nginx/sites-enabled/default \
    && ln -s /etc/nginx/sites-available/flask.conf /etc/nginx/sites-enabled/flask.conf \
    && echo "daemon off;" >> /etc/nginx/nginx.conf \
    && pip3 install -r /tmp/requirements.txt \
    && chown -R www-data:www-data /var/www/app \
    && chown -R www-data:www-data /var/log

CMD ["/usr/bin/supervisord"]

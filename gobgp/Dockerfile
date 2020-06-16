FROM alpine:3.12

RUN apk add --no-cache python3 && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
    apk add --no-cache wget

COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt \
  && wget https://github.com/osrg/gobgp/releases/download/v2.8.0/gobgp_2.8.0_linux_amd64.tar.gz \
  && tar -xzvf gobgp_2.8.0_linux_amd64.tar.gz \
  && mkdir /root/gobgp \
  && mv gobgp /root/gobgp/gobgp \
  && mv gobgpd /root/gobgp/gobgpd \
  && chmod +x /root/gobgp/gobgp \
  && chmod +x /root/gobgp/gobgpd
COPY ./gobgpd.conf /root/gobgp/gobgpd.conf
COPY ./entrypoint.sh /root/gobgp/entrypoint.sh
COPY ./startup.sh /root/gobgp/startup.sh
RUN chmod +x /root/gobgp/entrypoint.sh \
  && chmod +x /root/gobgp/startup.sh
ENTRYPOINT [ "/root/gobgp/entrypoint.sh" ]
FROM osrg/gobgp:latest

RUN apt-get update && apt-get install -y \
    python3
RUN apt-get update && apt-get install -y \
    python3-pip
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt
COPY ./gobgpd.conf /root/gobgp/gobgpd.conf
COPY ./entrypoint.sh /root/gobgp/entrypoint.sh
RUN chmod +x /root/gobgp/entrypoint.sh
COPY ./startup.sh /root/gobgp/startup.sh
RUN chmod +x /root/gobgp/startup.sh
ENTRYPOINT /root/gobgp/entrypoint.sh
# ENTRYPOINT gobgpd -f /root/gobgp/gobgpd.conf
# RUN gobgp global rib -a ipv6 -j > /var/tmp/log/ipv6-rib.json
# RUN gobgp global rib -a ipv4 -j > /var/tmp/log/ipv4-rib.json
# RUN gobgp monitor global rib -j > /var/tmp/log/updates.json &

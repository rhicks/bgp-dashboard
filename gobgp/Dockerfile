# FROM osrg/gobgp:latest
FROM ubuntu:17.10

RUN apt-get update
RUN apt-get remove -y binutils
RUN apt-get install -y python3.6
RUN apt-get install -y python3-pip
RUN apt-get install -y wget
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt
RUN wget https://github.com/osrg/gobgp/releases/download/v1.32/gobgp_1.32_linux_amd64.tar.gz
RUN tar -xzvf gobgp_1.32_linux_amd64.tar.gz
RUN mkdir /root/gobgp
RUN mv gobgp /root/gobgp/gobgp
RUN mv gobgpd /root/gobgp/gobgpd
RUN chmod +x /root/gobgp/gobgp
RUN chmod +x /root/gobgp/gobgpd
COPY ./gobgpd.conf /root/gobgp/gobgpd.conf
COPY ./entrypoint.sh /root/gobgp/entrypoint.sh
RUN chmod +x /root/gobgp/entrypoint.sh
COPY ./startup.sh /root/gobgp/startup.sh
RUN chmod +x /root/gobgp/startup.sh
ENTRYPOINT /root/gobgp/entrypoint.sh

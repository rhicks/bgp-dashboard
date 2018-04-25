FROM osrg/gobgp:latest

RUN echo "deb http://ftp.debian.org/debian testing main" >> /etc/apt/sources.list
RUN apt-get update && apt-get remove -y binutils
RUN apt-get update && apt-get install -y python3.6
RUN apt-get update && apt-get install -y python3-pip
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt
COPY ./gobgpd.conf /root/gobgp/gobgpd.conf
COPY ./entrypoint.sh /root/gobgp/entrypoint.sh
RUN chmod +x /root/gobgp/entrypoint.sh
COPY ./startup.sh /root/gobgp/startup.sh
RUN chmod +x /root/gobgp/startup.sh
ENTRYPOINT /root/gobgp/entrypoint.sh

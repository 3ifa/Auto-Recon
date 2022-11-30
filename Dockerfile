FROM ubuntu:18.04
FROM python:3.9-buster
RUN apt update
RUN rm -rf /var/cache/apt/*
RUN apt install -y git
RUN git clone https://github.com/3ifa/Auto-Recon.git
WORKDIR /Auto-Recon
RUN pip3 install wheel
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
CMD  ["python3","app.py"]
EXPOSE 80
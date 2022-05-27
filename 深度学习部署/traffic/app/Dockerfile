FROM python:3.7

MAINTAINER hanzhuang hanzhuang42@foxmail.com

ADD . /app

WORKDIR /app

EXPOSE 9999:9999/udp

RUN pip install --upgrade pip

RUN python -m pip install --upgrade setuptools

RUN pip install -i https://mirrors.aliyun.com/pypi/simple/ -r requirements.txt

CMD python /app/traffic_classification.py

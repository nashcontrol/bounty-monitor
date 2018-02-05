FROM python:2.7-alpine

RUN apk update && \
    apk add --virtual build-deps gcc python-dev musl-dev libffi-dev openssl-dev
ADD requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
ADD . /bounty-monitor
WORKDIR /bounty-monitor
CMD [ "python", "./bounty-monitor.py" ] ...
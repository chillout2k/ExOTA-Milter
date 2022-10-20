ARG PARENT_IMAGE=alpine:3.16
FROM ${PARENT_IMAGE}
LABEL maintainer="Dominik Chilla <dominik@zwackl.de>"
LABEL git_repo="https://github.com/chillout2k/exota-milter"

ADD ./requirements.txt /requirements.txt

RUN apk update \
  && apk add python3 python3-dev py3-pip gcc libc-dev libmilter-dev \
  && pip3 install -r requirements.txt \
  && apk del gcc libc-dev libmilter-dev python3-dev py3-pip \
  && apk add libmilter \
  && adduser -D exota-milter \
  && install -d -o exota-milter /socket /data \
  && rm -rf /var/cache/apk/* /requirements.txt

ADD ./app/ /app/
ADD ./OCI/cmd /cmd
RUN chown -R exota-milter /app /cmd \
  && chmod -R +x /app /cmd

# Default file policy path: /data/policy.json
VOLUME [ "/socket", "/data" ]

USER exota-milter
CMD [ "/cmd" ]

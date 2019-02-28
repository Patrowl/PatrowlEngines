FROM alpine:3.8
MAINTAINER Patrowl.io "sgetupport@patrowl.io"
LABEL Name="SSLScan\ \(Patrowl engine\)" Version="1.0.0"

# Set the working directory
RUN mkdir -p /opt/patrowl-engines/sslscan
RUN mkdir -p /opt/patrowl-engines/sslscan/results
WORKDIR /opt/patrowl-engines/sslscan

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-sslscan.py .
COPY sslscan.json.sample sslscan.json
COPY requirements.txt .
COPY README.md .

WORKDIR /opt/patrowl-engines/sslscan/libs
RUN apk add --no-cache build-base git perl zlib-dev libc6-compat && \
    git clone https://github.com/rbsec/sslscan.git && \
    cd sslscan && \
    make static && make install && \
    cd / && rm -rf sslscan && \
    apk del .build-deps build-base git perl zlib-dev libc6-compat

#WORKDIR /opt/patrowl-engines/sslscan/libs
#RUN apk add --no-cache curl bash procps drill git coreutils
#RUN rm -rf /var/cache/apk/* /tmp/*
#RUN git clone --depth=1 https://github.com/drwetter/testssl.sh.git .


WORKDIR /opt/patrowl-engines/sslscan
RUN pip install --upgrade pip
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5014

# Run app.py when the container launches
USER nobody
CMD ["gunicorn", "engine-sslscan:app", "-b", "0.0.0.0:5014"]

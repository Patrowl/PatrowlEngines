FROM ubuntu:16.04
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Arachni\ \(Patrowl engine\)" Version="1.0.0"

ENV VERSION_FRAMEWORK 1.5.1
ENV VERSION_ARACHNI $VERSION_FRAMEWORK-0.5.12
ENV TGZ_ARACHNI arachni-$VERSION_ARACHNI-linux-x86_64.tar.gz
ENV DL_ARACHNI_LINK https://s3-eu-west-1.amazonaws.com/patrowl/engines/arachni/libs/$TGZ_ARACHNI

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/arachni
RUN mkdir -p /opt/patrowl-engines/arachni/results
RUN mkdir -p /opt/patrowl-engines/arachni/libs
RUN mkdir -p /opt/patrowl-engines/arachni/logs

# Set the working directory to /opt/patrowl-engines/<engine_name>
WORKDIR /opt/patrowl-engines/arachni

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-arachni.py .
COPY arachni.json.sample arachni.json
COPY requirements.txt .
COPY README.md .

WORKDIR /opt/patrowl-engines/arachni/libs

RUN apt-get -qq update && apt-get install -yq wget ruby bash python3 python3-pip bsdtar make gcc && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN ln -sf $(which bsdtar) $(which tar)
RUN wget $DL_ARACHNI_LINK -nv
RUN tar xzf $TGZ_ARACHNI && \
rm -f $TGZ_ARACHNI && \
ln -sf /opt/patrowl-engines/arachni/libs/arachni-$VERSION_ARACHNI /opt/patrowl-engines/arachni/libs/arachni && \
useradd -m -s /bin/sh user && \
echo "Success"

ENV PATH /opt/patrowl-engines/arachni/libs/arachni/bin:$PATH
RUN pip3 install --upgrade pip setuptools
RUN pip3 install -r /opt/patrowl-engines/arachni/requirements.txt

WORKDIR /opt/patrowl-engines/arachni/

# TCP port exposed by the container (NAT)
EXPOSE 5005

# Run app.py when the container launches
CMD ["gunicorn", "engine-arachni:app", "-k", "gevent", "-w", "1", "-b", "0.0.0.0:5005", "--preload"]

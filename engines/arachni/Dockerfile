FROM debian:jessie
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Arachni\ \(Patrowl engine\)" Version="1.0.0"

ENV VERSION_FRAMEWORK 1.5.1
ENV VERSION_ARACHNI $VERSION_FRAMEWORK-0.5.12

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

RUN apt-get -qq update && apt-get install -yq wget ruby bash python python-pip && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /opt/patrowl-engines/arachni/libs
RUN wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz -nv
RUN tar xzf arachni-$VERSION_ARACHNI-linux-x86_64.tar.gz && \
rm -f arachni-$VERSION_ARACHNI-linux-x86_64.tar.gz && \
ln -sf /opt/patrowl-engines/arachni/libs/arachni-$VERSION_ARACHNI /opt/patrowl-engines/arachni/libs/arachni && \
useradd -m -s /bin/sh user && \
echo "Success"

ENV PATH /opt/patrowl-engines/arachni/libs/arachni/bin:$PATH
RUN pip install -r /opt/patrowl-engines/arachni/requirements.txt

WORKDIR /opt/patrowl-engines/arachni/

# TCP port exposed by the container (NAT)
EXPOSE 5105

# Run app.py when the container launches
#CMD ["python", "engine-arachni.py"]
CMD ["gunicorn", "engine-arachni:app", "-b", "0.0.0.0:5105"]

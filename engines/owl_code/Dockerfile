FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Patrowl\ Code\ Security\ review\ \(Patrowl engine\)" Version="1.0.0"

# Install dependencies
RUN apk add --update \
    wget unzip openjdk8-jre git subversion \
    python \
    python-dev \
    py-pip \
    nodejs nodejs-npm \
  && rm -rf /var/cache/apk/*

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/owl_code
RUN mkdir -p /opt/patrowl-engines/owl_code/results
RUN mkdir -p /opt/patrowl-engines/owl_code/libs
RUN mkdir -p /opt/patrowl-engines/owl_code/utils

# Copy the Patrowl dependencies
ADD utils /opt/patrowl-engines/owl_code/utils

# Set the working directory to /opt/<engine_name>
WORKDIR /tmp/

# Install Retire.js
RUN npm install -g retire

# Install OWASP-DC
ENV version_url=https://jeremylong.github.io/DependencyCheck/current.txt
ENV download_url=https://dl.bintray.com/jeremy-long/owasp
RUN wget -qO- -O /tmp/current.txt ${version_url}                            && \
    version=$(cat /tmp/current.txt)                                         && \
    file="dependency-check-${version}-release.zip"                          && \
    wget "$download_url/$file"                                              && \
    unzip ${file}                                                           && \
    rm ${file}                                                              && \
    mv dependency-check /opt/patrowl-engines/owl_code/libs                  && \
    cd /opt/patrowl-engines/owl_code/libs                                   && \
    chmod +x dependency-check/bin/dependency-check.sh                       && \
    dependency-check/bin/dependency-check.sh --updateonly

# Set the working directory to /opt/<engine_name>
WORKDIR /opt/patrowl-engines/owl_code

# Copy the current directory contents into the container at /
COPY owl_code/__init__.py .
COPY owl_code/engine-owl_code.py .
COPY owl_code/requirements.txt .
COPY owl_code/owl_code.json.sample owl_code.json

# Install python modules
RUN pip install --upgrade pip
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5013

# Run app.py when the container launches
CMD ["python", "engine-owl_code.py", "--port=5013", "--host=0.0.0.0"]

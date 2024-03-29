FROM alpine:3.16.3
LABEL Name="Patrowl\ Code\ Security\ review\ \(Patrowl engine\)" Version="1.4.30"

# Install dependencies
RUN apk add --update --no-cache \
    wget unzip openjdk8-jre \
    git subversion \
    python3 python3-dev py3-pip \
    npm nodejs \
  && rm -rf /var/cache/apk/* \
  && rm -rf /tmp/*

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/owl_code
RUN mkdir -p /opt/patrowl-engines/owl_code/results
RUN mkdir -p /opt/patrowl-engines/owl_code/libs
RUN mkdir -p /opt/patrowl-engines/owl_code/utils

# Set the working directory to /opt/<engine_name>
WORKDIR /tmp/

# Install Retire.js
RUN npm install -g retire

# Install OWASP-DC
ENV version_url=https://jeremylong.github.io/DependencyCheck/current.txt
# ENV download_url=https://dl.bintray.com/jeremy-long/owasp
ENV download_url=https://github.com/jeremylong/DependencyCheck/releases/download/
RUN wget -qO- -O /tmp/current.txt ${version_url}                            && \
    version=$(cat /tmp/current.txt)                                         && \
    # version="6.0.3"                                         && \
    # file="dependency-check-6.0.3-release.zip"                               && \
    # file="dependency-check-${version}-release.zip"                          && \
    file="dependency-check-${version}-release.zip"                          && \
    wget "$download_url/v${version}/$file"                                  && \
    unzip ${file}                                                           && \
    rm ${file}                                                              && \
    mv dependency-check /opt/patrowl-engines/owl_code/libs                  && \
    cd /opt/patrowl-engines/owl_code/libs                                   && \
    chmod +x dependency-check/bin/dependency-check.sh
RUN dependency-check/bin/dependency-check.sh --updateonly ; exit 0

# Set the working directory to /opt/<engine_name>
WORKDIR /opt/patrowl-engines/owl_code

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-owl_code.py .
COPY requirements.txt .
COPY owl_code.json.sample owl_code.json
COPY VERSION .

# Install python modules
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org --ignore-installed -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5013

# Run app.py when the container launches
CMD ["python3", "engine-owl_code.py", "--port=5013", "--host=0.0.0.0"]

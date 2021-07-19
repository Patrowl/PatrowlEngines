# FROM ubuntu:18.04
FROM ubuntu:20.04
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Patrowl\ DNS\ \(Patrowl engine\)" Version="1.4.27"

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-dnspython \
    python3-geoip python3-whois python3-requests python3-ssdeep \
    python3-pip python3-setuptools python3-dev git wget locales && \
    locale-gen en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US.UTF-8

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/owl_dns
RUN mkdir -p /opt/patrowl-engines/owl_dns/results
RUN mkdir -p /opt/patrowl-engines/owl_dns/external-libs

# Set the working directory to /opt/<engine_name>
WORKDIR /opt/patrowl-engines/owl_dns

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-owl_dns.py .
COPY owl_dns.json.sample owl_dns.json
COPY requirements.txt .
COPY README.md .
COPY etc/ etc/
COPY modules/ modules/
WORKDIR /opt/patrowl-engines/owl_dns/external-libs
RUN git clone https://github.com/Patrowl/Sublist3r
WORKDIR /opt/patrowl-engines/owl_dns/external-libs/Sublist3r
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
WORKDIR /opt/patrowl-engines/owl_dns/external-libs
RUN git clone https://github.com/elceef/dnstwist
WORKDIR /opt/patrowl-engines/owl_dns/external-libs/dnstwist
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# Install python modules for engine
WORKDIR /opt/patrowl-engines/owl_dns/
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5006

# Run app.py when the container launches
CMD ["gunicorn", "engine-owl_dns:app", "-b", "0.0.0.0:5006", "--access-logfile", "-", "--threads", "10"]

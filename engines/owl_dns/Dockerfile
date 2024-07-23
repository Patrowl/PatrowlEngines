FROM alpine:3.16.3
LABEL Name="Patrowl\ DNS\ \(Patrowl engine\)" Version="1.5.10"

# Install dependencies
RUN apk add --update --no-cache \
  python3 python3-dev py3-pip \
  git \
  build-base linux-headers \
  && rm -rf /var/cache/apk/*

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/owl_dns
RUN mkdir -p /opt/patrowl-engines/owl_dns/results
RUN mkdir -p /opt/patrowl-engines/owl_dns/external-libs

WORKDIR /opt/patrowl-engines/owl_dns/external-libs
RUN git clone https://github.com/Patrowl/Sublist3r
WORKDIR /opt/patrowl-engines/owl_dns/external-libs/Sublist3r
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
WORKDIR /opt/patrowl-engines/owl_dns/external-libs
RUN git clone https://github.com/elceef/dnstwist

# Set the working directory to /opt/<engine_name>
WORKDIR /opt/patrowl-engines/owl_dns

# Install python modules for engine
COPY requirements.txt .
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine_owl_dns.py .
COPY owl_dns.json.sample owl_dns.json
COPY README.md .
COPY VERSION .
COPY etc/ etc/
COPY modules/ modules/

# TCP port exposed by the container (NAT)
EXPOSE 5006

# Run app.py when the container launches
CMD ["gunicorn", "engine_owl_dns:app", "-b", "0.0.0.0:5006", "--access-logfile", "-", "--threads", "10"]

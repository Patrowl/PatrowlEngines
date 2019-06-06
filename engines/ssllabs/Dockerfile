FROM python:3.7

RUN mkdir -p /opt/patrowl-engines/ssllabs/results

WORKDIR /opt/patrowl-engines/ssllabs

COPY . .
COPY ssllabs.json.sample ssllabs.json

# Temporary
COPY utils ../utils

RUN pip3 install --no-cache-dir -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5004

# Run the application when the container launches
CMD ["gunicorn", "engine-ssllabs:app", "-b", "0.0.0.0:5004", "--timeout", "120", "--graceful-timeout", "60"]

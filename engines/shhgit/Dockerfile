FROM alpine:3.16.3
LABEL Name="SHHGit\ \(Patrowl engine\)" Version="1.4.33"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/shhgit
RUN mkdir -p /opt/patrowl-engines/shhgit/results
RUN mkdir -p /opt/patrowl-engines/shhgit/data
RUN mkdir -p /opt/patrowl-engines/shhgit/libs

# Install any needed packages specified in requirements.txt
RUN apk add --update --no-cache \
    python3 python3-dev py3-pip \
    gcc libc-dev libffi-dev make git \
  && rm -rf /var/cache/apk/*

# Clone sast-git-leaks
WORKDIR /opt/patrowl-engines/shhgit/libs
RUN git clone https://github.com/leboncoin/sast-git-leaks/
RUN ls -al
RUN ls -al sast-git-leaks
RUN sed -e 's/sast_git_leaks.tools/libs.sast_git_leaks.sast_git_leaks.tools/g' sast-git-leaks/config/variables.py > sast-git-leaks/config/variables.py.bak && mv sast-git-leaks/config/variables.py.bak sast-git-leaks/config/variables.py

# Copy the current directory contents into the container at /
WORKDIR /opt/patrowl-engines/shhgit
COPY __init__.py .
COPY engine-shhgit.py .
COPY libs/github.py libs/github.py
COPY libs/git_leaks.py libs/git_leaks.py
COPY shhgit.json.sample shhgit.json
COPY requirements.txt .
COPY README.md .
COPY VERSION .

# Install python requirements
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
RUN pip3 install --trusted-host pypi.python.org -r libs/sast-git-leaks/requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5025

# Run app.py when the container launches
CMD ["gunicorn", "engine-shhgit:app", "-b", "0.0.0.0:5025", "--access-logfile", "-"]

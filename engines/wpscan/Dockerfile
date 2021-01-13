FROM ruby:2.7.1-alpine AS builder

# ENV WP_VERSION v3.8.7
ENV WP_VERSION v3.8.13
RUN echo "install: --no-document --no-post-install-message\nupdate: --no-document --no-post-install-message" > /etc/gemrc

RUN apk add --no-cache git libcurl ruby-dev libffi-dev make gcc musl-dev zlib-dev procps sqlite-dev

RUN git clone https://github.com/wpscanteam/wpscan /wpscan
WORKDIR /wpscan
# RUN cd /wpscan && ls -l && git tag
RUN git checkout $WP_VERSION

RUN bundle config force_ruby_platform true && \
  bundle config disable_version_check 'true' && \
  bundle config without "test development" && \
  bundle config path.system 'true' && \
  bundle install --gemfile=/wpscan/Gemfile --jobs=8


RUN rake install --trace

# needed so non superusers can read gems
RUN chmod -R a+r /usr/local/bundle

# -- WPScan Deployment
FROM ruby:2.7.1-alpine

RUN adduser -h /wpscan -g WPScan -D wpscan
COPY --from=builder /usr/local/bundle /usr/local/bundle
RUN chown -R wpscan:wpscan /wpscan

# runtime dependencies
RUN apk add --no-cache libcurl procps sqlite-libs
WORKDIR /wpscan

# USER wpscan

RUN /usr/local/bundle/bin/wpscan --update --verbose

# -- Patrowl Engine
# FROM alpine:latest
# MAINTAINER Patrowl.io "getsupport@patrowl.io"
# LABEL Name="Wpscan\ \(Patrowl engine\)" Version="1.4.12"
#
# COPY --from=builderruby /usr/local/bundle/bin/wpscan /usr/bin/wpscan

# Install dependencies
RUN apk add --update --no-cache \
    python3 \
    python3-dev \
    py3-pip \
    git \
    gcc \
    musl-dev \
    libc-dev \
    linux-headers \
  && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/patrowl-engines/wpscan
RUN mkdir -p /opt/patrowl-engines/wpscan/results

WORKDIR /opt/patrowl-engines/wpscan

COPY __init__.py .
COPY engine-wpscan.py .
COPY wpscan.json.sample wpscan.json
COPY requirements.txt .
COPY README.md .

RUN pip3 install --no-cache-dir -U pip wheel setuptools
RUN pip3 install --no-cache-dir -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5023

# Run the application when the container launches
CMD ["gunicorn", "engine-wpscan:app", "-b", "0.0.0.0:5023", "--timeout", "120", "--graceful-timeout", "60", "--access-logfile", "-"]

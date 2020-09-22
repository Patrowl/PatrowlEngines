TRUSTED_HOSTS="--trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org"

echo "[+] Install OWL_DNS engine"

echo "[+] Install OS dependencies"
if [ "$(uname)" == "Darwin" ]; then # MacOs
  brew install nmap python3
  export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
elif [ -f /etc/lsb-release ]; then # Ubuntu/Debian
  sudo apt-get install nmap nmap-scripts python3 python3-pip
elif [ -f /etc/redhat-release ]; then # Centos/RedHat
  sudo yum install nmap python3 python3-pip
fi

echo "[+] Install Python modules"
# Install virtualenv
pip3 install virtualenv
rm -rf env
virtualenv env --python=python3
env/bin/pip install -r requirements.txt $TRUSTED_HOSTS

echo "[+] Install external deps"
cd external-libs
git clone https://github.com/Patrowl/Sublist3r
pip3 install --trusted-host pypi.python.org -r Sublist3r/requirements.txt
RUN git clone https://github.com/elceef/dnstwist
cd ..

echo "[+] Create config file from sample"
if [ ! -f owl_dns.json ]; then
  cp owl_dns.json.sample owl_dns.json
fi

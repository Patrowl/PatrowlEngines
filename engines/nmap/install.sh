TRUSTED_HOSTS="--trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org"

echo "[+] Install NMAP engine"

echo "[+] Install OS dependencies"
if [ "$(uname)" == "Darwin" ]; then # MacOs
  brew install nmap python3 jq
elif [ -f /etc/lsb-release ]; then # Ubuntu/Debian
  sudo apt-get install nmap nmap-scripts python3 python3-pip jq
elif [ -f /etc/redhat-release ]; then # Centos/RedHat
  sudo yum install nmap python3 python3-pip jq
fi

echo "[+] Install Python modules"
# Install virtualenv
pip3 install virtualenv
rm -rf env
virtualenv env --python=python3
env/bin/pip install -r requirements.txt $TRUSTED_HOSTS

echo "[+] Create config file from sample"
if [ ! -f nmap.json ]; then
  cp nmap.json.sample nmap.json
  cat nmap.json | jq '.path = $new_path' --arg new_path `which nmap` > nmap.json
fi

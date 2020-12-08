## Installation script for OpenVAS/Greenbone 20.08 on Ubuntu 20.08
## Based on:
# https://kifarunix.com/install-and-setup-gvm-11-on-ubuntu-20-04/#create-gvm-service-unit-file
# https://github.com/yu210148/gvm_install/blob/master/install_gvm.sh

apt-get update && apt-get upgrade
useradd -r -d /opt/gvm -c "GVM User" -s /bin/bash gvm
mkdir /opt/gvm
chown gvm:gvm /opt/gvm
apt install gcc g++ make bison flex libksba-dev curl redis libpcap-dev \
cmake git pkg-config libglib2.0-dev libgpgme-dev nmap libgnutls28-dev uuid-dev \
libssh-gcrypt-dev libldap2-dev gnutls-bin libmicrohttpd-dev libhiredis-dev \
zlib1g-dev libxml2-dev libradcli-dev clang-format libldap2-dev doxygen \
gcc-mingw-w64 xml-twig-tools libical-dev perl-base heimdal-dev libpopt-dev \
libsnmp-dev python3-setuptools python3-paramiko python3-lxml python3-defusedxml python3-dev gettext python3-polib xmltoman \
python3-pip texlive-fonts-recommended texlive-latex-extra --no-install-recommends xsltproc -y

# Install Yarn
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
apt update
apt install yarn -y

# Install PostgreSQL
apt install postgresql postgresql-contrib postgresql-server-dev-all -y
sudo -Hiu postgres
createuser gvm
createdb -O gvm gvmd
psql gvmd
create role dba with superuser noinherit;
grant dba to gvm;
create extension "uuid-ossp";
\q
exit

systemctl restart postgresql
systemctl enable postgresql

# Building GVM 20 from Source Code
cp /etc/environment /etc/environment.bck
echo PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin\" > /etc/environment
echo "/opt/gvm/lib" > /etc/ld.so.conf.d/gvm.conf


# Build and Install GVM 20
su - gvm
mkdir /tmp/gvm-source
cd /tmp/gvm-source
git clone -b gvm-libs-20.08 https://github.com/greenbone/gvm-libs.git
git clone https://github.com/greenbone/openvas-smb.git
git clone -b openvas-20.08 https://github.com/greenbone/openvas.git
git clone -b ospd-20.08 https://github.com/greenbone/ospd.git
git clone -b ospd-openvas-20.08 https://github.com/greenbone/ospd-openvas.git
git clone -b gvmd-20.08 https://github.com/greenbone/gvmd.git
git clone -b gsa-20.08 https://github.com/greenbone/gsa.git
ls
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH

# Build and Install GVM Libraries
cd gvm-libs
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install

# Build and Install OpenVAS scanner and OpenVAS SMB
cd ../../openvas-smb/
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install

cd ../../openvas
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install

# Configuring OpenVAS Scanner
exit
ldconfig
cp /tmp/gvm-source/openvas/config/redis-openvas.conf /etc/redis/
chown redis:redis /etc/redis/redis-openvas.conf
echo "db_address = /run/redis-openvas/redis.sock" > /opt/gvm/etc/openvas/openvas.conf
chown gvm:gvm /opt/gvm/etc/openvas/openvas.conf
usermod -aG redis gvm
echo "net.core.somaxconn = 1024" >> /etc/sysctl.conf
echo 'vm.overcommit_memory = 1' >> /etc/sysctl.conf
sysctl -p

cat <<EOT > /etc/systemd/system/disable_thp.service
[Unit]
Description=Disable Kernel Support for Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target
EOT

systemctl daemon-reload
systemctl enable --now disable_thp
systemctl enable --now redis-server@openvas
echo "gvm ALL = NOPASSWD: /opt/gvm/sbin/openvas" > /etc/sudoers.d/gvm
sed 's/Defaults\s.*secure_path=\"\/usr\/local\/sbin:\/usr\/local\/bin:\/usr\/sbin:\/usr\/bin:\/sbin:\/bin:\/snap\/bin\"/Defaults secure_path=\"\/usr\/local\/sbin:\/usr\/local\/bin:\/usr\/sbin:\/usr\/bin:\/sbin:\/bin:\/snap\/bin:\/opt\/gvm\/sbin\"/g' /etc/sudoers | EDITOR='tee' visudo
echo "gvm ALL = NOPASSWD: /opt/gvm/sbin/gsad" >> /etc/sudoers.d/gvm

# Update NVTs
su - gvm
greenbone-nvt-sync --rsync
sudo openvas --update-vt-info

# Build and Install Greenbone Vulnerability Manager
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
cd /tmp/gvm-source/gvmd
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install

# Build and Install Greenbone Security Assistant
cd ../../gsa
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm
make
make install

# Update GVM CERT and SCAP data from the feed servers;
greenbone-scapdata-sync --rsync
greenbone-certdata-sync --rsync
greenbone-feed-sync --type GVMD_DATA
gvm-manage-certs -a


# Build and Install OSPd and OSPd-OpenVAS
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
mkdir -p /opt/gvm/lib/python3.8/site-packages/
export PYTHONPATH=/opt/gvm/lib/python3.8/site-packages
cd /tmp/gvm-source/ospd
python3 setup.py install --prefix=/opt/gvm
cd ../ospd-openvas
python3 setup.py install --prefix=/opt/gvm

# Start OpenVAS Scanner, GSA and GVM services
/usr/bin/python3 /opt/gvm/bin/ospd-openvas \
--pid-file /opt/gvm/var/run/ospd-openvas.pid \
--log-file /opt/gvm/var/log/gvm/ospd-openvas.log \
--lock-file-dir /opt/gvm/var/run -u /opt/gvm/var/run/ospd.sock
gvmd --osp-vt-update=/opt/gvm/var/run/ospd.sock
sudo gsad

ps aux | grep -E "ospd-openvas|gsad|gvmd" | grep -v grep


# Create OpenVAS service
sudo su -
cat <<EOT > /etc/systemd/system/openvas.service
[Unit]
Description=Control the OpenVAS service
After=redis.service
After=postgresql.service

[Service]
ExecStartPre=-rm -rf /opt/gvm/var/run/ospd-openvas.pid /opt/gvm/var/run/ospd.sock /opt/gvm/var/run/gvmd.sock
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
Environment=PYTHONPATH=/opt/gvm/lib/python3.8/site-packages
ExecStart=/usr/bin/python3 /opt/gvm/bin/ospd-openvas \
--pid-file /opt/gvm/var/run/ospd-openvas.pid \
--log-file /opt/gvm/var/log/gvm/ospd-openvas.log \
--lock-file-dir /opt/gvm/var/run -u /opt/gvm/var/run/ospd.sock
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOT

systemctl daemon-reload
systemctl start openvas
# systemctl status openvas
systemctl enable openvas

# Create GSA Service Unit file
cat <<EOT > /etc/systemd/system/gsa.service
[Unit]
Description=Control the OpenVAS GSA service
After=openvas.service

[Service]
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
Environment=PYTHONPATH=/opt/gvm/lib/python3.8/site-packages
ExecStart=/usr/bin/sudo /opt/gvm/sbin/gsad --mlisten=0.0.0.0 --mport=9392
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOT

cat <<EOT > /etc/systemd/system/gsa.path
[Unit]
Description=Start the OpenVAS GSA service when gvmd.sock is available

[Path]
PathChanged=/opt/gvm/var/run/gvmd.sock
Unit=gsa.service

[Install]
WantedBy=multi-user.target
EOT

# Create GVM Service unit file
cat <<EOT > /etc/systemd/system/gvm.service
[Unit]
Description=Control the OpenVAS GVM service
After=openvas.service

[Service]
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
Environment=PYTHONPATH=/opt/gvm/lib/python3.8/site-packages
ExecStart=/opt/gvm/sbin/gvmd --osp-vt-update=/opt/gvm/var/run/ospd.sock --listen=0.0.0.0 --port=9392
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOT

cat <<EOT > /etc/systemd/system/gvm.path
[Unit]
Description=Start the OpenVAS GVM service when opsd.sock is available

[Path]
PathChanged=/opt/gvm/var/run/ospd.sock
Unit=gvm.service

[Install]
WantedBy=multi-user.target
EOT

systemctl daemon-reload
systemctl enable --now openvas
systemctl enable --now gvm.{path,service}
systemctl enable --now gsa.{path,service}

# Create GVM Scanner
# sudo -Hiu gvm gvmd --create-scanner="Patrowl OpenVAS Scanner" --scanner-type="OpenVAS" --scanner-host=/opt/gvm/var/run/ospd.sock
sudo -Hiu gvm gvmd --get-scanners
# --> modify scanner changing sock: --scanner-host=/opt/gvm/var/run/ospd.sock
SCANNER_UUID=$(sudo -Hiu gvm gvmd --get-scanners | grep OpenVAS | cut -f1 -d" ")
sudo -Hiu gvm gvmd --modify-scanner=$SCANNER_UUID --scanner-host=/opt/gvm/var/run/ospd.sock
sudo -Hiu gvm gvmd --verify-scanner=$SCANNER_UUID


# Create OpenVAS (GVM) Admin User
sudo -Hiu gvm gvmd --create-user gvmadmin --password="Bonjour1**GVM"
# sudo -Hiu gvm gvmd --user=gvmadmin --new-password="Bonjour1**GVM"

# Add the user as import feed owner
USER_UUID=$(sudo -Hiu gvm gvmd --get-users --verbose | cut -f2 -d" ")
sudo -Hiu gvm gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value $USER_UUID

#!/bin/bash
set -euo pipefail

function prompt() {
    while true; do
        read -p "$1 [y/N] " yn
        case $yn in
            [Yy] ) return 0;;
            [Nn]|"" ) return 1;;
        esac
    done
}

if [[ $(id -u) != 0 ]]; then
    echo 请以root用户身份运行此脚本
    exit 1
fi

if [[ $(uname -m 2> /dev/null) != x86_64 ]]; then
    echo 请在x86_64机器上运行此脚本
    exit 1
fi

echo "输入域名: "
read newname
echo "输入防火墙SSH要开放的端口: "
read ssh_prot

SSMGR_PASSWD=$(openssl rand -base64 12)
SYSTEMDPREFIX="/etc/systemd/system"
SUFFIX=.tar.gz
NG_NAME=nginx
NG_VERSION=$(curl -s 'http://nginx.org/en/download.html' | sed 's/</\'$'\n''</g' | sed -n '/>Stable version$/,$ p' | grep 'tar.gz' | sed 's/.*tar.gz">nginx-//' | head -n 1)
NG_TARBALL="${NG_NAME}-${NG_VERSION}${SUFFIX}"
NG_DOWNLOADURL="https://nginx.org/download/${NG_TARBALL}"
NG_CONFIG_URL="https://raw.githubusercontent.com/syscca/nginx-trojan/master/nginx.conf"
NG_CONFIG="/etc/nginx/nginx.conf"
NG_SYSTEMDPATH="${SYSTEMDPREFIX}/${NG_NAME}.service"

PCRE_NAME=pcre
PCRE_VERSION=8.45
PCRE_TARBALL="${PCRE_NAME}-${PCRE_VERSION}${SUFFIX}"
PCRE_DOWNLOADURL="https://ftp.exim.org/pub/pcre/${PCRE_TARBALL}"
# https://ftp.exim.org/pub/pcre/pcre-8.44.tar.gz

ZLIB_NAME=zlib
ZLIB_VERSION=$(curl -s 'https://zlib.net' | sed 's/</\'$'\n''</g' | sed -n '/Current release:/,$ p' | grep '<B> ' | sed 's/<B> zlib //' | head -n 1)
ZLIB_TARBALL="${ZLIB_NAME}-${ZLIB_VERSION}${SUFFIX}"
ZLIB_DOWNLOADURL="http://zlib.net/${ZLIB_TARBALL}"
# http://zlib.net/zlib-1.2.11.tar.gz

SSL_VERSION=$(curl -fsSL https://api.github.com/repos/openssl/openssl/releases | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -n 1)
SSL_TARBALL="${SSL_VERSION}${SUFFIX}"
SSL_DOWNLOADURL="https://github.com/openssl/openssl/releases/download/${SSL_VERSION}/${SSL_VERSION}${SUFFIX}"

SSLCER="/etc/nginx/ssl/syscca.com/fullchain.cer"
SSLKEY="/etc/nginx/ssl/syscca.com/syscca.com.key"
SSLFILE="/etc/nginx/ssl"

TJ_NAME=trojan-go
TJ_VERSION=v0.5.1
#$(curl -fsSL https://api.github.com/repos/p4gefau1t/trojan-go/releases | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -n 1)
TJ_TARBALL="${TJ_NAME}-linux-amd64.zip"
TJ_DOWNLOADURL="https://github.com/p4gefau1t/${TJ_NAME}/releases/download/${TJ_VERSION}/${TJ_TARBALL}"
TJ_INSTALLPREFIX=/usr/local

TJ_BINARYPATH="${TJ_INSTALLPREFIX}/bin/${TJ_NAME}"
TJ_CONFIGPATH="${TJ_INSTALLPREFIX}/etc/${TJ_NAME}/config.json"
TJ_SYSTEMDPATH="${SYSTEMDPREFIX}/${TJ_NAME}.service"
# https://github.com/p4gefau1t/trojan-go/releases/download/v0.5.1/trojan-go-linux-amd64.zip

echo "刷新源..."
apt update
echo "安装软件pssh wget socat qrencode curl xz unzip build-essential redis-server..."
apt install pssh wget socat qrencode curl xz-utils unzip build-essential redis-server openssl -y

ymname="/etc/nginx/conf.d/${newname}.conf"
wwip=$(curl -fsSL https://ipv4.jsonip.com | grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}")

TMPDIR="$(mktemp -d)"

echo "进入临时文件夹 ${TMPDIR}..."
cd "${TMPDIR}"

off_log(){
if systemctl is-active --quiet rsyslog; then
    echo "停止和禁止syslog..."
    service rsyslog stop
    systemctl disable rsyslog
else
    echo "syslog 没有运行"
fi
}

key_ssh(){
echo "add ssh key..."
mkdir -p ~/.ssh
cat > ~/.ssh/id_rsa << EOF
私钥
EOF
chmod 600 /root/.ssh/id_rsa
cat > ~/.ssh/authorized_keys << EOF
公钥
EOF
}

off_ssh_pass(){
echo "关闭ssh密码登录..."
sed -i 's/^#\?\(PasswordAuthentication\s*\).*$/\1no/' /etc/ssh/sshd_config
}


set_time(){
echo "设置上海时区..."
echo "Asia/Shanghai" > /etc/timezone && \
rm /etc/localtime && \
dpkg-reconfigure -f noninteractive tzdata
}

setup_swap(){
    isSwapOn=$(swapon -s | tail -1)
    if [[ ${isSwapOn} == "" ]]; then
        add_swap
    else
        del_swap
        add_swap
    fi
    echo "Setup swap complete! Check output to confirm everything is good."
}

del_swap() {
    echo "del swap..."
    backupTime=$(date +%y-%m-%d--%H-%M-%S)
    swapSpace=$(swapon --show=NAME --noheadings | tail -n1)
    if [ -n "$swapSpace" ]; then
        echo "3" > /proc/sys/vm/drop_caches
        swapoff $swapSpace
        cp /etc/fstab /etc/fstab.$backupTime
        sed -i '/swap/d' /etc/fstab
        rm -rf "$swapSpace"
    else
        echo "没有找到 swap 空间，不执行删除操作。"
    fi
}

add_swap(){
echo "add swap..."
dd if=/dev/zero of=/swapfile bs=1024k count=1000
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo "/swapfile none swap sw 0 0" >> /etc/fstab
}

fw_save(){
if [[ `command -v iptables-save` ]];then
    echo "iptables 已经安装"
else
echo "安装 iptables..."
apt install iptables -y
fi

echo "安装iptables-persistent..."
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt -y install iptables-persistent

echo "清空防火墙..."
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -F
ip6tables -X

echo "添加防火墙规则..."
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW --dport ${ssh_prot} -j ACCEPT
#iptables -A INPUT -p tcp --dport 25 -j ACCEPT
#iptables -A INPUT -p tcp --dport 465 -j ACCEPT
iptables -A INPUT -p tcp --dport 4001 -j ACCEPT
iptables -A INPUT -p udp --dport 4001 -j ACCEPT
#iptables -A INPUT -p tcp --dport 3306 -j ACCEPT
#iptables -A INPUT -p tcp --dport 6001 -j ACCEPT
#iptables -A INPUT -p udp --dport 6001 -j ACCEPT
#iptables -A INPUT -p tcp --dport 6002 -j ACCEPT
#iptables -A INPUT -p udp --dport 6002 -j ACCEPT
#iptables -A INPUT -p udp --dport 51820 -j ACCEPT
#iptables -A INPUT -p tcp --dport 7000:7500 -j ACCEPT
#iptables -A INPUT -p udp --dport 7000:7500 -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -j REJECT

echo "保存iptables 防火墙规则..."
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
}

setup_bbr(){
LSBBR=$(sysctl net.ipv4.tcp_congestion_control)
if [[ ${LSBBR} =~ "bbr" ]]; then
echo "已开启BBR"
else
echo "正在开启BBR"
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
fi
}

set_user(){
NG_USER=$(awk -F: '$0~/nginx/' /etc/passwd|wc -l)
if [[ ${NG_USER} -ne 0 ]]; then
echo "nginx 组和用户已存在..."
else
echo "正在创建 nginx 组和用户..."
groupadd nginx
useradd -M -g nginx -s /sbin/nologin nginx
fi
}

setup_nginx(){
echo "下载 ${NG_NAME}-$NG_VERSION..."
curl -LO --progress-bar "${NG_DOWNLOADURL}" || wget -q --show-progress "${NG_DOWNLOADURL}"

echo "下载 ${PCRE_NAME}-${PCRE_VERSION}..."
curl -LO --progress-bar "${PCRE_DOWNLOADURL}" || wget -q --show-progress "${PCRE_DOWNLOADURL}"

echo "下载 ${ZLIB_NAME}-${ZLIB_VERSION}..."
curl -LO --progress-bar "${ZLIB_DOWNLOADURL}" || wget -q --show-progress "${ZLIB_DOWNLOADURL}"

echo "下载 ${SSL_VERSION}..."
curl -LO --progress-bar "${SSL_DOWNLOADURL}" || wget -q --show-progress "${SSL_DOWNLOADURL}"

echo "解压 ${NG_NAME}-${NG_VERSION}..."
tar -zxf "${NG_TARBALL}"

echo "解压 ${PCRE_NAME}-${PCRE_VERSION}..."
tar -zxf "${PCRE_TARBALL}"

echo "解压 ${ZLIB_NAME}-${ZLIB_VERSION}..."
tar -zxf "${ZLIB_TARBALL}"

echo "解压 ${SSL_VERSION}..."
tar -zxf "${SSL_TARBALL}"

echo "configure ${NG_NAME}-${NG_VERSION}..."
cd ./${NG_NAME}-${NG_VERSION}
./configure \
--prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx \
--modules-path=/usr/lib/nginx/modules \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/var/run/nginx.pid \
--lock-path=/var/run/nginx.lock \
--http-client-body-temp-path=/var/cache/nginx/client_temp \
--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
--user=nginx \
--group=nginx \
--with-compat \
--with-file-aio \
--with-threads \
--with-http_addition_module \
--with-http_auth_request_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_mp4_module \
--with-http_random_index_module \
--with-http_realip_module \
--with-http_secure_link_module \
--with-http_slice_module \
--with-http_ssl_module \
--with-http_stub_status_module \
--with-http_sub_module \
--with-http_v2_module \
--with-mail \
--with-mail_ssl_module \
--with-stream \
--with-stream_realip_module \
--with-stream_ssl_module \
--with-stream_ssl_preread_module \
--with-pcre=../${PCRE_NAME}-${PCRE_VERSION} \
--with-zlib=../${ZLIB_NAME}-${ZLIB_VERSION} \
--with-openssl=../${SSL_VERSION} \
--with-cc-opt='-g -O2 -ffile-prefix-map=../'${NG_NAME}-${NG_VERSION}'=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
--with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie'

echo "编译 ${NG_NAME}-${NG_VERSION}..."
make

echo "编译安装 ${NG_NAME}-${NG_VERSION}..."
make install

if [[ ! -d "/etc/nginx/conf.d" ]]; then
echo "新建/etc/nginx/conf.d文件夹..."
mkdir -p /etc/nginx/conf.d
else
echo "/etc/nginx/conf.d文件夹已创建..."
fi

if [[ ! -d "/var/www/${newname}" ]]; then
echo "新建/var/www/${newname}文件夹..."
mkdir -p "/var/www/${newname}"
else
echo "/var/www/${newname}文件夹已创建..."
fi

if [[ ! -d "${SSLFILE}" ]]; then
echo "新建${SSLFILE}文件夹..."
mkdir -p "${SSLFILE}"
else
echo "${SSLFILE}文件夹已创建..."
fi

if [[ ! -d "/var/cache/nginx/client_temp" ]]; then
echo "新建/var/cache/nginx/client_temp文件夹..."
mkdir -p /var/cache/nginx/client_temp
else
echo "/var/cache/nginx/client_temp文件夹已创建..."
fi

echo "下载 ${NG_NAME} ${NG_VERSION} CONFIG File..."
curl -LO --progress-bar "${NG_CONFIG_URL}" || wget -q --show-progress "${NG_CONFIG_URL}"

echo 复制 ${NG_NAME}.conf 到 ${NG_CONFIG}...
cp -rf "./${NG_NAME}.conf" "${NG_CONFIG}"

if [ -f "/var/www/${newname}/index.html" ];then
echo "/var/www/${newname}/index.html文件已存在"
else
echo "正在创建 /var/www/${newname}/index.html..."
cat > /var/www/${newname}/index.html << EOF
<html>

<head>
<title>null</title>
</head>

<body>
<p>body 404</p>
<p>title Not Found</p>
</body>

</html>
EOF
fi

echo "添加 /var/www/${newname} 权限..."
chown -R nginx:nginx "/var/www/${newname}"

if [[ -f "${ymname}" ]];then
  echo "${ymname}文件已存在"
  else
echo "正在创建 ${ymname}..."
cat > ${ymname} << EOF
server {

  listen 127.0.0.1:80 default_server;
  server_name ${newname};
  index index.html;
  root /var/www/${newname};
}
server {

  listen 127.0.0.1:80;
  server_name ${wwip};
  return 301 https://${newname}\$request_uri;
}

server {
  listen 0.0.0.0:80;
  listen [::]:80;
  server_name _;
  return 301 https://\$host\$request_uri;
}
EOF
fi

if [[ -f "${NG_SYSTEMDPATH}" ]];then
  echo "${NG_SYSTEMDPATH}文件存在"
  else
echo "正在创建 ${NG_SYSTEMDPATH}..."
cat > "${NG_SYSTEMDPATH}" <<EOF
[Unit]
Description=nginx - high performance web server
Documentation=http://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/sh -c "/bin/kill -s HUP \$(/bin/cat /var/run/nginx.pid)"
ExecStop=/bin/sh -c "/bin/kill -s TERM \$(/bin/cat /var/run/nginx.pid)"

[Install]
WantedBy=multi-user.target
EOF
fi

echo "Downloading fullchain.cer..."
if [[ -f "/etc/nginx/ssl/syscca.com/syscca.com.key" ]];then
echo "syscca.com.key 文件已存在..."
else
echo "下载证书/etc/nginx/ssl/"
scp -o StrictHostKeyChecking=no -r root@主域名:/etc/nginx/ssl /etc/nginx/
fi

echo "Reloading systemd daemon..."
systemctl daemon-reload

if systemctl is-active --quiet nginx; then
echo "强制停止和禁止 nginx..."
killall -9 nginx
systemctl disable nginx
else
echo "nginx没有运行"
fi

echo "restart nginx..."
systemctl restart nginx

echo "enable nginx..."
systemctl enable nginx
}

setup_redis(){
echo "配置 redis..."
sed -i 's/^#\?\(supervised\s*\).*$/\1systemd/' /etc/redis/redis.conf
echo "重启 redis..."
systemctl restart redis
}

setup_trojan(){
echo "下载 ${TJ_NAME}-${TJ_VERSION}..."
curl -LO --progress-bar "${TJ_DOWNLOADURL}" || wget -q --show-progress "${TJ_DOWNLOADURL}"

echo "解压安装 ${TJ_NAME}-${TJ_VERSION}..."
unzip -d /usr/local/bin "${TJ_TARBALL}"

echo "chmod 755 ${TJ_BINARYPATH}..."
chmod 755 "${TJ_BINARYPATH}"

mkdir -p ${TJ_INSTALLPREFIX}/etc/${TJ_NAME}
echo "配置 ${TJ_CONFIGPATH}..."
cat > "${TJ_CONFIGPATH}" << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "${SSMGR_PASSWD}"
    ],
    "ssl": {
        "cert": "${SSLCER}",
        "key": "${SSLKEY}"
    },
    "redis": {
        "enabled": true,
        "server_addr": "127.0.0.1",
        "server_port": 6379
    }
}
EOF

echo "配置 ${TJ_SYSTEMDPATH}..."
cat > "${TJ_SYSTEMDPATH}" << EOF
[Unit]
Description=Trojan-Go - An unidentifiable mechanism that helps you bypass GFW
Documentation=https://github.com/p4gefau1t/trojan-go
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/trojan-go -config /usr/local/etc/trojan-go/config.json
Restart=on-failure
RestartSec=10s
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

echo "chmod 644 ${TJ_SYSTEMDPATH}..."
chmod 644 "${TJ_SYSTEMDPATH}"

echo "Reloading systemd daemon..."
systemctl daemon-reload

if systemctl is-active --quiet trojan-go; then
    echo "强制停止和禁止 trojan..."
        killall -9 trojan-go
    systemctl disable trojan-go
else
    echo "systemctl trojan-go没有运行"
fi

echo "start trojan..."
systemctl start trojan-go

echo "enable trojan"
systemctl enable trojan-go
}

setup_nodejs(){
echo "源加nodejs 18.x 源..."
curl -sL https://deb.nodesource.com/setup_18.x | bash -
echo "安装nodejs 18.x..."
apt install nodejs -y
echo "安装pm2..."
npm i -g pm2
echo "安装ssmgr-trojan-client..."
npm i -g ssmgr-trojan-client
echo "添加pm2开机启动ssmgr-trojan-client..."
pm2 --name ssmgrtjc -f start ssmgr-trojan-client -x -- -k ${SSMGR_PASSWD} >> /dev/null 2>&1
pm2 save && pm2 startup
echo "删除 ${TMPDIR}..."
rm -rf "${TMPDIR}"
echo "节点域名：${newname} 节点端口：4001 节点密码： ${SSMGR_PASSWD}"
}

off_log
set_time
key_ssh
off_ssh_pass
setup_swap
fw_save
setup_bbr
set_user
setup_nginx
setup_redis
setup_trojan
setup_nodejs

#!/bin/bash

# 颜色定义
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

# 检查是否为 root 用户和 x86_64 架构
check_root_and_arch() {
    if [[ $(id -u) != 0 ]]; then
        echo -e "${WHT}错误：请以 root 用户身份运行此脚本${RESET}"
        exit 1
    fi
    if [[ $(uname -m) != "x86_64" ]]; then
        echo -e "${WHT}错误：请在 x86_64 架构机器上运行此脚本${RESET}"
        exit 1
    fi
}

# 获取并验证用户输入
get_user_input() {
    read -p "${GREEN}输入域名（如 example.com）: ${RESET}" DOMAIN
    read -p "${GREEN}输入防火墙 SSH 要开放的端口（默认回车为 22）: ${RESET}" SSH_PORT
    read -p "${GREEN}粘贴公钥: ${RESET}" PUBLIC_KEY
    echo -e "${GREEN}粘贴私钥 (以 EOF 结尾):${RESET}"
    PRIVATE_KEY=$(cat << 'EOF'
    # 请在此粘贴您的私钥
EOF
)
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=22
    fi
    # 验证域名格式
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}错误：域名格式无效${RESET}"
        exit 1
    fi
    # 验证端口号
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        echo -e "${RED}错误：SSH 端口号必须在 1-65535 之间${RESET}"
        exit 1
    fi
    CLEAN_DOMAIN=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
    SSMGR_PASSWD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12)
    echo -e "${GREEN}用户输入完成：域名=$DOMAIN, SSH 端口=$SSH_PORT${RESET}, 公钥=${PUBLIC_KEY} 私钥=${PRIVATE_KEY}"
}

# 安装基础软件并检查安装结果
install_base_software() {
    apt update && apt upgrade -y || { echo -e "${RED}错误：系统更新失败${RESET}"; exit 1; }
    apt install -y pssh wget socat qrencode curl xz-utils gnupg2 ca-certificates lsb-release debian-archive-keyring redis-server ufw zram-tools || { echo -e "${RED}错误：软件安装失败${RESET}"; exit 1; }
    echo -e "${GREEN}基础软件安装完成${RESET}"
}

# 获取公网 IP
get_public_ip() {
    PUBLIC_IP=$(curl -fsSL myip.ipip.net | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    if [[ -z "$PUBLIC_IP" ]]; then
        echo -e "${RED}错误：无法获取公网 IP${RESET}"
        exit 1
    fi
    echo -e "${GREEN}公网 IP 获取完成：$PUBLIC_IP${RESET}"
}

# 关闭日志服务
off_log() {
    if systemctl is-active --quiet rsyslog; then
        systemctl stop rsyslog && systemctl disable rsyslog || { echo -e "${RED}错误：关闭日志服务失败${RESET}"; exit 1; }
        echo -e "${GREEN}日志服务已关闭并禁用${RESET}"
    else
        echo -e "${YELLOW}日志服务未运行，无需操作${RESET}"
    fi
}

# 设置 SSH 密钥并禁用密码登录
key_ssh() {
    mkdir -p ~/.ssh || { echo -e "${RED}错误：创建 SSH 目录失败${RESET}"; exit 1; }
    echo "${PUBLIC_KEY} admin@${CLEAN_DOMAIN}" > ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    echo "${PRIVATE_KEY}" > ~/.ssh/id_rsa 
    chmod 600 ~/.ssh/id_rsa
    sed -i 's/^#\?\(PasswordAuthentication\s*\).*$/\1no/' /etc/ssh/sshd_config || { echo -e "${RED}错误：修改 SSH 配置失败${RESET}"; exit 1; }
    systemctl restart sshd || { echo -e "${RED}错误：重启 SSH 服务失败${RESET}"; exit 1; }
    echo -e "${GREEN}SSH 密钥设置完成${RESET}"
}

# 设置时区
set_time() {
    echo "Asia/Shanghai" > /etc/timezone
    rm -f /etc/localtime
    dpkg-reconfigure -f noninteractive tzdata || { echo -e "${RED}错误：设置时区失败${RESET}"; exit 1; }
    echo -e "${GREEN}时区设置完成${RESET}"
}

# 设置 Swap 分区
setup_swap() {
    swap_files=$(swapon --show=NAME --noheadings)
    if [[ -n "$swap_files" ]]; then
        for swap_file in $swap_files; do
            echo "3" > /proc/sys/vm/drop_caches
            swapoff "$swap_file" && rm -f "$swap_file" || { echo -e "${RED}错误：删除现有 Swap 分区失败${RESET}"; exit 1; }
            echo -e "${YELLOW}删除现有交换分区：$swap_file${RESET}"
        done
        cp /etc/fstab /etc/fstab.backup
        sed -i '/swap/d' /etc/fstab
        echo -e "${GREEN}备份 /etc/fstab 完成${RESET}"
    fi
    echo "PERCENT=50" | tee /etc/default/zramswap
    systemctl enable zramswap && systemctl start zramswap || { echo -e "${RED}错误：配置 zram 失败${RESET}"; exit 1; }
    echo -e "${GREEN}zram 分区配置完成${RESET}"
}

# 配置防火墙
setup_firewall() {
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow "${SSH_PORT}/tcp"
    ufw allow 4001/tcp
    ufw allow 4001/udp
    ufw --force enable || { echo -e "${RED}错误：启用防火墙失败${RESET}"; exit 1; }
    echo -e "${GREEN}防火墙配置完成${RESET}"
}

# 启用 BBR
setup_bbr() {
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p || { echo -e "${RED}错误：启用 BBR 失败${RESET}"; exit 1; }
        echo -e "${GREEN}BBR 启用成功${RESET}"
    else
        echo -e "${YELLOW}BBR 已启用，无需重复配置${RESET}"
    fi
}

# 配置 Redis
setup_redis() {
    if systemctl is-active --quiet redis-server; then
        echo -e "${GREEN}Redis-server 正在运行${RESET}"
    else
        echo -e "${YELLOW}Redis-server 未运行，尝试重启...${RESET}"
        systemctl restart redis-server || { echo -e "${RED}错误：重启 Redis 服务失败${RESET}"; exit 1; }
    fi
}

# 安装和配置 Nginx
setup_nginx() {
    curl -s https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | tee /etc/apt/preferences.d/99nginx
    apt update && apt install -y nginx || { echo -e "${RED}错误：Nginx 安装失败${RESET}"; exit 1; }
    if systemctl is-active --quiet nginx; then
        systemctl stop nginx || { echo -e "${RED}错误：停止 Nginx 失败${RESET}"; exit 1; }
    fi
    rm -rf /etc/nginx/conf.d/*
    wget -q --show-progress --no-check-certificate "https://raw.githubusercontent.com/syscca/nginx-trojan/master/nginx.conf" -O /etc/nginx/nginx.conf || { echo -e "${RED}错误：下载 Nginx 配置文件失败${RESET}"; exit 1; }
    cat > "/etc/nginx/conf.d/${DOMAIN}.conf" << EOF
server {
  listen 127.0.0.1:80 default_server;
  server_name ${DOMAIN};
  index index.html;
  root /usr/share/nginx/html;
}
server {
  listen 127.0.0.1:80;
  server_name ${PUBLIC_IP};
  return 301 https://${DOMAIN}\$request_uri;
}
server {
  listen 0.0.0.0:80;
  server_name _;
  return 301 https://\$host\$request_uri;
}
EOF
    scp -o StrictHostKeyChecking=no -r "root@${CLEAN_DOMAIN}:/etc/nginx/ssl" /etc/nginx/ || { echo -e "${RED}错误：复制 SSL 文件失败${RESET}"; exit 1; }
    if nginx -t; then
        systemctl daemon-reload
        systemctl restart nginx && systemctl enable nginx || { echo -e "${RED}错误：启动 Nginx 失败${RESET}"; exit 1; }
        echo -e "${GREEN}Nginx 配置完成${RESET}"
    else
        echo -e "${RED}错误：Nginx 配置测试失败，请检查配置文件${RESET}"
        exit 1
    fi
}

# 安装和配置 Trojan-Go
setup_trojan() {
    if systemctl is-active --quiet trojan-go; then
        systemctl stop trojan-go || { echo -e "${RED}错误：停止 Trojan-Go 失败${RESET}"; exit 1; }
    fi
    wget -q --show-progress --no-check-certificate "https://github.com/p4gefau1t/trojan-go/releases/download/v0.5.1/trojan-go-linux-amd64.zip" -O trojan-go.zip || { echo -e "${RED}错误：下载 Trojan-Go 失败${RESET}"; exit 1; }
    unzip -o trojan-go.zip -d /usr/local/bin/ && chmod 755 /usr/local/bin/trojan-go || { echo -e "${RED}错误：安装 Trojan-Go 失败${RESET}"; exit 1; }
    mkdir -p /usr/local/etc/trojan-go
    cat > /usr/local/etc/trojan-go/config.json << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["${SSMGR_PASSWD}"],
    "ssl": {
        "cert": "/etc/nginx/ssl/${CLEAN_DOMAIN}/fullchain.cer",
        "key": "/etc/nginx/ssl/${CLEAN_DOMAIN}/${CLEAN_DOMAIN}.key"
    },
    "redis": {
        "enabled": true,
        "server_addr": "127.0.0.1",
        "server_port": 6379
    }
}
EOF
    cat > /etc/systemd/system/trojan-go.service << EOF
[Unit]
Description=Trojan-Go Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/trojan-go -config /usr/local/etc/trojan-go/config.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl restart trojan-go && systemctl enable trojan-go || { echo -e "${RED}错误：启动 Trojan-Go 失败${RESET}"; exit 1; }
    echo -e "${GREEN}Trojan-Go 配置完成${RESET}"
}

# 安装和配置 Node.js
setup_nodejs() {
    # 安装 Node.js
    curl -sL https://deb.nodesource.com/setup_18.x | bash -
    apt install -y nodejs || { echo -e "${RED}错误：Node.js 安装失败${RESET}"; exit 1; }
    
    # 全局安装 pm2 和 ssmgr-trojan-client
    npm i -g pm2 ssmgr-trojan-client || { echo -e "${RED}错误：安装 pm2 或 ssmgr-trojan-client 失败${RESET}"; exit 1; }
    
    # 检查并清理 ssmgrtjc 进程
    if pm2 list | grep -q "ssmgrtjc"; then
        pm2 stop ssmgrtjc || true
        pm2 delete ssmgrtjc || true
    fi
    
    # 启动 ssmgrtjc 进程
    pm2 --name ssmgrtjc -f start ssmgr-trojan-client -x -- -k "${SSMGR_PASSWD}" >/dev/null 2>&1
    
    # 保存 PM2 配置并设置开机启动
    pm2 save --force && pm2 startup || { echo -e "${RED}错误：配置 pm2 失败${RESET}"; exit 1; }
    
    echo -e "${GREEN}Node.js 和 ssmgr-trojan-client 配置完成${RESET}"
}

# 显示服务状态和调试信息
status_show() {
    echo -e "${YELLOW}===== 查看所有应用服务状态 =====${RESET}"
    systemctl status redis-server nginx trojan-go --no-pager
    pm2 list
    echo -e "${YELLOW}===== 调试命令 =====${RESET}"
    echo "systemctl status|start|stop|restart|enable|disable redis-server nginx trojan-go"
    echo "pm2 start|restart|stop|delete|save|startup|unstartup"
    echo "ssmgr-trojan-client -k ${SSMGR_PASSWD}"
    echo "/usr/bin/nginx -config /etc/nginx/nginx.conf"
    echo "/usr/local/bin/trojan-go -config /usr/local/etc/trojan-go/config.json"
    echo -e "${YELLOW}===== 节点信息 =====${RESET}"
    echo "节点域名：${DOMAIN} 节点端口：4001 节点密码：${SSMGR_PASSWD}"
}

# 主函数
main() {
    check_root_and_arch
    TMPDIR="$(mktemp -d)" || { echo -e "${RED}错误：创建临时目录失败${RESET}"; exit 1; }
    cd "${TMPDIR}"
    trap 'rm -rf "${TMPDIR}"; exit' EXIT  # 确保脚本退出时清理临时目录
    get_user_input
    install_base_software
    get_public_ip
    off_log
    set_time
    key_ssh
    setup_swap
    setup_firewall
    setup_bbr
    setup_redis
    setup_nginx
    setup_trojan
    setup_nodejs
    status_show
    rm -rf "${TMPDIR}"
    echo -e "${GREEN}所有应用服务配置完成${RESET}"
}

# 执行主函数
main

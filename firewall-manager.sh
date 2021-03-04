#!/bin/bash
# https://github.com/complexorganizations/server-firewall

# Require script to be run as root
function super-user-check() {
  if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as super user."
    exit
  fi
}

# Check for root
super-user-check

# Detect Operating System
function dist-check() {
  if [ -e /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO=${ID}
  fi
}

# Check Operating System
dist-check

SSHD_CONFIG="/etc/ssh/sshd_config"
NGINX_CONFIG="/etc/nginx/nginx.conf"
FIRWALL_MANAGER_PATH="/etc/firewall-manager"
FIRWALL_MANAGER="${FIRWALL_MANAGER_PATH}/firewall-manager"

# Install the firewall
function install-firewall() {
  if { [ "${DISTRO}" == "ubuntu" ] || [ "${DISTRO}" == "debian" ] || [ "${DISTRO}" == "raspbian" ] || [ "${DISTRO}" == "pop" ] || [ "${DISTRO}" == "kali" ] || [ "${DISTRO}" == "linuxmint" ] || [ "${DISTRO}" == "fedora" ] || [ "${DISTRO}" == "centos" ] || [ "${DISTRO}" == "rhel" ] || [ "${DISTRO}" == "arch" ] || [ "${DISTRO}" == "manjaro" ] || [ "${DISTRO}" == "alpine" ] || [ "${DISTRO}" == "freebsd" ]; }; then
    if { [ ! -x "$(command -v sed)" ] || [ ! -x "$(command -v curl)" ] || [ ! -x "$(command -v jq)" ] || [ ! -x "$(command -v ufw)" ] || [ ! -x "$(command -v fail2ban)" ] || [ ! -x "$(command -v ssh)" ] || [ ! -x "$(command -v openssl)" ] || [ ! -x "$(command -v lsof)" ]; }; then
      if { [ "${DISTRO}" == "ubuntu" ] || [ "${DISTRO}" == "debian" ] || [ "${DISTRO}" == "raspbian" ] || [ "${DISTRO}" == "pop" ] || [ "${DISTRO}" == "kali" ] || [ "${DISTRO}" == "linuxmint" ]; }; then
        apt-get update
        apt-get install haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof -y
      elif { [ "${DISTRO}" == "fedora" ] || [ "${DISTRO}" == "centos" ] || [ "${DISTRO}" == "rhel" ]; }; then
        yum update -y
        yum install haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof -y
      elif { [ "${DISTRO}" == "arch" ] || [ "${DISTRO}" == "manjaro" ]; }; then
        pacman -Syu
        pacman -Syu --noconfirm haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof
      elif [ "${DISTRO}" == "alpine" ]; then
        apk update
        apk add haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof
      elif [ "${DISTRO}" == "freebsd" ]; then
        pkg update
        pkg install haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof
      fi
    fi
  else
    echo "Error: ${DISTRO} not supported."
    exit
  fi
}

# Install the firewall
install-firewall

function configure-firewall() {
  # SSH
  if [ -x "$(command -v sshd)" ]; then
    if [ -f "${SSHD_CONFIG}" ]; then
      sed -i "s|PasswordAuthentication yes|PasswordAuthentication no|" ${SSHD_CONFIG}
      sed -i "s|#PermitEmptyPasswords no|PermitEmptyPasswords no|" ${SSHD_CONFIG}
      sed -i "s|AllowTcpForwarding yes|AllowTcpForwarding no|" ${SSHD_CONFIG}
      sed -i "s|PermitRootLogin yes|PermitRootLogin no|" ${SSHD_CONFIG}
      sed -i "s|#MaxAuthTries 6|MaxAuthTries 3|" ${SSHD_CONFIG}
      sed -i "s|X11Forwarding yes|X11Forwarding no|" ${SSHD_CONFIG}
      sed -i "s|#LogLevel INFO|LogLevel VERBOSE|" ${SSHD_CONFIG}
      sed -i "s|#Port 22|Port 22|" ${SSHD_CONFIG}
      sed -i "s|#PubkeyAuthentication yes|PubkeyAuthentication yes|" ${SSHD_CONFIG}
      sed -i "s|#ChallengeResponseAuthentication no|ChallengeResponseAuthentication yes|" ${SSHD_CONFIG}
    fi
  fi
  # UFW
  if [ -x "$(command -v ufw)" ]; then
    ufw default allow incoming
    ufw default allow outgoing
  fi
  # Nginx
  if [ -x "$(command -v nginx)" ]; then
    if [ -f "${NGINX_CONFIG}" ]; then
      sed -i "s|# server_tokens off|server_tokens off|" ${NGINX_CONFIG}
    fi
  fi
}

configure-firewall

function create-user() {
  if [ ! -f "${FIRWALL_MANAGER}" ]; then
    LINUX_USERNAME="$(openssl rand -hex 5)"
    LINUX_PASSWORD="$(openssl rand -hex 10)"
    useradd -m -s /bin/bash "${LINUX_USERNAME}"
    echo -e "${LINUX_PASSWORD}\n${LINUX_PASSWORD}" | passwd "${LINUX_USERNAME}"
    usermod -aG sudo "${LINUX_USERNAME}"
    if [ ! -d "/home/${LINUX_USERNAME}/.ssh/" ]; then
      mkdir -p /home/${LINUX_USERNAME}/.ssh/
      chmod 600 /home/${LINUX_USERNAME}/.ssh/
    fi
    ssh-keygen -o -a 2500 -t ed25519 -f /home/${LINUX_USERNAME}/.ssh/id_ed25519 -N "${LINUX_PASSWORD}"
    PUBLIC_SSH_KEY="$(cat /home/"${LINUX_USERNAME}"/.ssh/id_ed25519.pub)"
    PRIVATE_SSH_KEY="$(cat /home/"${LINUX_USERNAME}"/.ssh/id_ed25519)"
    echo "${PUBLIC_SSH_KEY}" >> /home/"${LINUX_USERNAME}"/.ssh/authorized_keys  
    echo "Linux Information"
    echo "Username: ${LINUX_USERNAME}"
    echo "Password: ${LINUX_PASSWORD}"
    echo "Public Key: ${PUBLIC_SSH_KEY}"
    echo "Private Key: ${PRIVATE_SSH_KEY}"
  fi
}

create-user

function firwall-manager() {
  if [ ! -d "${FIRWALL_MANAGER_PATH}" ]; then
    mkdir -p ${FIRWALL_MANAGER_PATH}
    if [ ! -f "${FIRWALL_MANAGER}" ]; then
      echo "Firewall Manager: True" >>${FIRWALL_MANAGER}
    fi
  fi
}

firwall-manager

function enable-service() {
  if [ -x "$(command -v ssh)" ]; then
    if pgrep systemd-journal; then
      systemctl enable ssh
      systemctl restart ssh
    else
      service ssh enable
      service ssh restart
    fi
  fi
  if [ -x "$(command -v ufw)" ]; then
    if pgrep systemd-journal; then
      ufw --force enable
      systemctl enable ufw
      systemctl restart ufw
    else
      ufw --force enable
      service ufw enable
      service ufw restart
    fi
  fi
  if [ -x "$(command -v fail2ban)" ]; then
    if pgrep systemd-journal; then
      systemctl enable fail2ban
      systemctl restart fail2ban
    else
      service fail2ban enable
      service fail2ban restart
    fi
  fi
}

enable-service

function ufw-rules() {
  if [ -x "$(command -v ufw)" ]; then
    if [ "$(lsof -i TCP:22)" ]; then
      ufw allow 22/tcp
    fi
    if [ "$(lsof -i TCP:80)" ]; then
      ufw allow 80/tcp
    fi
    if [ "$(lsof -i TCP:443)" ]; then
      ufw allow 443/tcp
    fi
    if [ "$(lsof -i TCP:53)" ]; then
      ufw allow 53/tcp
    fi
    if [ "$(lsof -i UDP:53)" ]; then
      ufw allow 53/udp
    fi
    if [ "$(lsof -i UDP:51820)" ]; then
      ufw allow 51820/udp
    fi
  fi
}

ufw-rules

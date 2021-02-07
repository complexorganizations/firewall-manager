#!/bin/bash
# https://github.com/complexorganizations/server-firewall

# Require script to be run as root
function super-user-check() {
  if [ "$EUID" -ne 0 ]; then
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
    DISTRO=$ID
    DISTRO_VERSION=$VERSION_ID
  fi
}

# Check Operating System
dist-check

UFW_CONFIG="/etc/default/ufw"
SSH_CONFIG="~/.ssh/authorized_keys"
SSHD_CONFIG="/etc/ssh/sshd_config"

# Install the firewall
function install-firewall() {
  if { [ ! -x "$(command -v ufw)" ] || [ ! -x "$(command -v fail2ban)" ]; }; then
    if { [ "$DISTRO" == "ubuntu" ] || [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "raspbian" ] || [ "$DISTRO" == "pop" ] || [ "$DISTRO" == "kali" ] || [ "$DISTRO" == "linuxmint" ]; }; then
      apt-get update
      apt-get install haveged fail2ban ufw lsof -y
    elif { [ "$DISTRO" == "fedora" ] || [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; }; then
      yum update -y
      yum install haveged fail2ban ufw lsof -y
    elif { [ "$DISTRO" == "arch" ] || [ "$DISTRO" == "manjaro" ]; }; then
      pacman -Syu
      pacman -Syu --noconfirm haveged fail2ban ufw lsof
    elif [ "$DISTRO" == "alpine" ]; then
      apk update
      apk add haveged fail2ban ufw lsof
    elif [ "$DISTRO" == "freebsd" ]; then
      pkg update
      pkg install haveged fail2ban ufw lsof
    fi
  fi
}

# Install the firewall
install-firewall

function configure-firewall() {
  if [ -f "$SSHD_CONFIG" ]; then
    sed -i "s|#PasswordAuthentication yes|PasswordAuthentication no|" $SSHD_CONFIG
    sed -i "s|#PermitEmptyPasswords no|PermitEmptyPasswords no|" $SSHD_CONFIG
    sed -i "s|AllowTcpForwarding yes|AllowTcpForwarding no|" $SSHD_CONFIG
    sed -i "s|X11Forwarding yes|X11Forwarding no|" $SSHD_CONFIG
    sed -i "s|#LogLevel INFO|LogLevel VERBOSE|" $SSHD_CONFIG
    sed -i "s|#Port 22|Port 22|" $SSHD_CONFIG
    sed -i "s|#PubkeyAuthentication yes|PubkeyAuthentication yes|" $SSHD_CONFIG
    sed -i "s|#ChallengeResponseAuthentication no|ChallengeResponseAuthentication yes|" $SSHD_CONFIG
  fi
  if [ -x "$(command -v ufw)" ]; then
    sed -i "s|# IPV6=yes;|IPV6=yes;|" $UFW_CONFIG
    ufw default reject incoming
    ufw default allow outgoing
    ufw allow 22/tcp
  if
}

configure-firewall

function enable-service() {
  if pgrep systemd-journal; then
    systemctl enable ssh
    systemctl restart ssh
    ufw enable
    systemctl enable ufw
    systemctl restart ufw
    systemctl enable fail2ban
    systemctl restart fail2ban
  else
    service ssh enable
    service ssh restart
    ufw enable
    service ufw enable
    service ufw restart
    service fail2ban enable
    service fail2ban restart
  fi
}

enable-service

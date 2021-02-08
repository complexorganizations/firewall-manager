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
  fi
}

# Check Operating System
dist-check

UFW_CONFIG="/etc/default/ufw"
SSHD_CONFIG="/etc/ssh/sshd_config"
FAIL_TO_BAN_CONFIG="/etc/fail2ban/jail.conf"
NGINX_CONFIG="/etc/nginx/nginx.conf"
FIRWALL_MANAGER_UPDATE="https://raw.githubusercontent.com/complexorganizations/firewall-manager/main/firewall-manager.sh"
FIRWALL_MANAGER="/etc/firewall-manager/firewall-manager"

if [ ! -f "$FIRWALL_MANAGER" ]; then

  # Install the firewall
  function install-firewall() {
    if { [ ! -x "$(command -v ufw)" ] || [ ! -x "$(command -v fail2ban)" ] || [ ! -x "$(command -v ssh)" ] || [ ! -x "$(command -v openssl)" ]; }; then
      if { [ "$DISTRO" == "ubuntu" ] || [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "raspbian" ] || [ "$DISTRO" == "pop" ] || [ "$DISTRO" == "kali" ] || [ "$DISTRO" == "linuxmint" ]; }; then
        apt-get update
        apt-get install haveged fail2ban ufw lsof openssh-client openssh-server openssl -y
      elif { [ "$DISTRO" == "fedora" ] || [ "$DISTRO" == "centos" ] || [ "$DISTRO" == "rhel" ]; }; then
        yum update -y
        yum install haveged fail2ban ufw lsof openssh-client openssh-server openssl -y
      elif { [ "$DISTRO" == "arch" ] || [ "$DISTRO" == "manjaro" ]; }; then
        pacman -Syu
        pacman -Syu --noconfirm haveged fail2ban ufw lsof openssh-client openssh-server openssl
      elif [ "$DISTRO" == "alpine" ]; then
        apk update
        apk add haveged fail2ban ufw lsof openssh-client openssh-server openssl
      elif [ "$DISTRO" == "freebsd" ]; then
        pkg update
        pkg install haveged fail2ban ufw lsof openssh-client openssh-server openssl
      fi
    fi
  }

  # Install the firewall
  install-firewall

  function configure-firewall() {
    # SSH
    if [ -f "$SSHD_CONFIG" ]; then
      sed -i "s|#PasswordAuthentication yes|PasswordAuthentication no|" $SSHD_CONFIG
      sed -i "s|#PermitEmptyPasswords no|PermitEmptyPasswords no|" $SSHD_CONFIG
      sed -i "s|AllowTcpForwarding yes|AllowTcpForwarding no|" $SSHD_CONFIG
      sed -i "s|PermitRootLogin yes|PermitRootLogin no|" $SSHD_CONFIG
      sed -i "s|#MaxAuthTries 6|MaxAuthTries 3|" $SSHD_CONFIG
      sed -i "s|X11Forwarding yes|X11Forwarding no|" $SSHD_CONFIG
      sed -i "s|#LogLevel INFO|LogLevel VERBOSE|" $SSHD_CONFIG
      sed -i "s|#Port 22|Port 22|" $SSHD_CONFIG
      sed -i "s|#PubkeyAuthentication yes|PubkeyAuthentication yes|" $SSHD_CONFIG
      sed -i "s|#ChallengeResponseAuthentication no|ChallengeResponseAuthentication yes|" $SSHD_CONFIG
    fi
    # UFW
    if [ -x "$(command -v ufw)" ]; then
      sed -i "s|# IPV6=yes;|IPV6=yes;|" $UFW_CONFIG
      ufw default reject incoming
      ufw default allow outgoing
      ufw allow 22/tcp
    fi
    # Fail2Ban
    if [ -x "$(command -v fail2ban)" ]; then
      if [ -f "$FAIL_TO_BAN_CONFIG" ]; then
        sed -i "s|# bantime = 1h|bantime = 24h|" $FAIL_TO_BAN_CONFIG
      fi
    fi
    # Nginx
    if [ -x "$(command -v nginx)" ]; then
      if [ -f "$NGINX_CONFIG" ]; then
        sed -i "s|# server_tokens off|server_tokens off|" $NGINX_CONFIG
      fi
    fi
  }

  configure-firewall

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
        ufw enable
        systemctl enable ufw
        systemctl restart ufw
      else
        ufw enable
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

  function create-user() {
    # Change from password to ssh key
    if [ -f "$FIRWALL_MANAGER" ]; then
      PASSWORD="$(openssl rand -base64 50)"
      USERNAME="$(openssl rand -base64 10)"
      useradd -m -p $PASSWORD -s /bin/bash $USERNAME
      echo "Username: $USERNAME"
      echo "Password: $PASSWORD"
      echo "Root login has been disabled"
    fi
  }

else

  function what-to-do-next() {
    echo "What do you want to do?"
    echo "   1) Show WireGuard"
    echo "   2) Start WireGuard"
    echo "   3) Stop WireGuard"
    echo "   4) Restart WireGuard"
    echo "   5) Add WireGuard Peer"
    echo "   6) Remove WireGuard Peer"
    echo "   7) Reinstall WireGuard"
    echo "   8) Uninstall WireGuard"
    echo "   9) Update this script"
    echo "   10) Backup WireGuard"
    echo "   11) Restore WireGuard"
    until [[ "$WIREGUARD_OPTIONS" =~ ^[0-9]+$ ]] && [ "$WIREGUARD_OPTIONS" -ge 1 ] && [ "$WIREGUARD_OPTIONS" -le 11 ]; do
      read -rp "Select an Option [1-11]: " -e -i 1 WIREGUARD_OPTIONS
    done
    case $WIREGUARD_OPTIONS in
    1) # WG Show
      wg show
      ;;
    2) # Enable & Start Wireguard
      if pgrep systemd-journal; then
        systemctl enable wg-quick@$WIREGUARD_PUB_NIC
        systemctl start wg-quick@$WIREGUARD_PUB_NIC
      else
        service wg-quick@$WIREGUARD_PUB_NIC enable
        service wg-quick@$WIREGUARD_PUB_NIC start
      fi
      ;;
    esac
  }

fi

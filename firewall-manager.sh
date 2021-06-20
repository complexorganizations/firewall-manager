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

# Install the firewall
function install-firewall() {
  if { [ "${DISTRO}" == "ubuntu" ] || [ "${DISTRO}" == "debian" ] || [ "${DISTRO}" == "raspbian" ] || [ "${DISTRO}" == "pop" ] || [ "${DISTRO}" == "kali" ] || [ "${DISTRO}" == "linuxmint" ] || [ "${DISTRO}" == "fedora" ] || [ "${DISTRO}" == "centos" ] || [ "${DISTRO}" == "rhel" ] || [ "${DISTRO}" == "arch" ] || [ "${DISTRO}" == "manjaro" ] || [ "${DISTRO}" == "alpine" ] || [ "${DISTRO}" == "freebsd" ]; }; then
    if { [ ! -x "$(command -v sed)" ] || [ ! -x "$(command -v curl)" ] || [ ! -x "$(command -v jq)" ] || [ ! -x "$(command -v ufw)" ] || [ ! -x "$(command -v fail2ban)" ] || [ ! -x "$(command -v ssh)" ] || [ ! -x "$(command -v openssl)" ] || [ ! -x "$(command -v lsof)" ] || [ ! -x "$(command -v gpg)" ]; }; then
      if { [ "${DISTRO}" == "ubuntu" ] || [ "${DISTRO}" == "debian" ] || [ "${DISTRO}" == "raspbian" ] || [ "${DISTRO}" == "pop" ] || [ "${DISTRO}" == "kali" ] || [ "${DISTRO}" == "linuxmint" ]; }; then
        apt-get update
        apt-get install haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof gpg -y
      elif { [ "${DISTRO}" == "fedora" ] || [ "${DISTRO}" == "centos" ] || [ "${DISTRO}" == "rhel" ]; }; then
        yum update -y
        yum install haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof gpg -y
      elif { [ "${DISTRO}" == "arch" ] || [ "${DISTRO}" == "manjaro" ]; }; then
        pacman -Syu
        pacman -Syu --noconfirm haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof gpg
      elif [ "${DISTRO}" == "alpine" ]; then
        apk update
        apk add haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof gpg
      elif [ "${DISTRO}" == "freebsd" ]; then
        pkg update
        pkg install haveged fail2ban ufw lsof openssh-server openssh-client openssl jq curl sed lsof gpg
      fi
    fi
  else
    echo "Error: ${DISTRO} not supported."
    exit
  fi
}

# Install the firewall
install-firewall

SSHD_CONFIG="/etc/ssh/sshd_config"
NGINX_CONFIG="/etc/nginx/nginx.conf"
FIRWALL_MANAGER_PATH="/etc/firewall-manager"
FIRWALL_MANAGER="${FIRWALL_MANAGER_PATH}/firewall-manager"
SERVER_HOST="$(curl -4 -s 'https://api.ipengine.dev' | jq -r '.network.ip')"
INTERNAL_SERVER_HOST="$(ip route get 8.8.8.8 | grep src | sed 's/.*src \(.* \)/\1/g' | cut -f1 -d ' ')"
if [ -z "${SERVER_HOST}" ]; then
  SERVER_HOST="$(ip route get 8.8.8.8 | grep src | sed 's/.*src \(.* \)/\1/g' | cut -f1 -d ' ')"
fi
        
function configure-firewall() {
  if [ -x "$(command -v sshd)" ]; then
    if [ -f "${SSHD_CONFIG}" ]; then
      rm -f ${SSHD_CONFIG}
    fi
    if [ ! -f "${SSHD_CONFIG}" ]; then
      echo "Port 22
      PermitRootLogin no
      MaxAuthTries 3
      PasswordAuthentication no
      PermitEmptyPasswords no
      ChallengeResponseAuthentication no
      KerberosAuthentication no
      GSSAPIAuthentication no
      X11Forwarding no
      UsePAM yes
      X11Forwarding yes
      PrintMotd no
      PermitUserEnvironment no
      AllowAgentForwarding no
      AllowTcpForwarding no
      PermitTunnel no
      AcceptEnv LANG LC_*
      Subsystem sftp /usr/lib/openssh/sftp-server" >>${SSHD_CONFIG}
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
    LINUX_USERNAME="$(openssl rand -hex 10)"
    LINUX_PASSWORD="$(openssl rand -hex 25)"
    GPG_LINUX_PASSWORD="$(openssl rand -hex 25)"
    useradd -m -s /bin/bash "${LINUX_USERNAME}"
    echo -e "${LINUX_PASSWORD}\n${LINUX_PASSWORD}" | passwd "${LINUX_USERNAME}"
    USER_DIRECTORY="/home/${LINUX_USERNAME}"
    USER_SSH_FOLDER="${USER_DIRECTORY}/.ssh"
    mkdir -p "${USER_SSH_FOLDER}"
    chmod 700 "${USER_SSH_FOLDER}"
    PRIVATE_SSH_KEY="${USER_SSH_FOLDER}/id_ssh_ed25519"
    PUBLIC_SSH_KEY="${USER_SSH_FOLDER}/id_ssh_ed25519.pub"
    AUTHORIZED_KEY="${USER_SSH_FOLDER}/authorized_keys"
    ssh-keygen -o -a 2500 -t ed25519 -f "${PRIVATE_SSH_KEY}" -N "${LINUX_PASSWORD}" -C "${LINUX_USERNAME}@${SERVER_HOST}"
    cat "${PRIVATE_SSH_KEY}" >> "${AUTHORIZED_KEY}"
    chmod 600 "${AUTHORIZED_KEY}"
    chown -R "${LINUX_USERNAME}":"${LINUX_USERNAME}" "${USER_DIRECTORY}"
    gpg --full-generate-key --expert --batch <<EOF
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Passphrase: ${GPG_LINUX_PASSWORD}
Name-Real: ${LINUX_USERNAME}
Name-Email: ${LINUX_USERNAME}@${SERVER_HOST}
Expire-Date: 0
EOF
    PUBLIC_GPG_KEY="${USER_SSH_FOLDER}/id_gpg_ed25519.pub"
    PRIVATE_GPG_KEY="${USER_SSH_FOLDER}/id_gpg_ed25519"
    gpg --output "${PUBLIC_GPG_KEY}" --armor --export "${LINUX_USERNAME}@${SERVER_HOST}"
    #gpg --output "${PRIVATE_GPG_KEY}" --armor --export-secret-key "${LINUX_USERNAME}@${SERVER_HOST}"
    echo "System External IP: ${SERVER_HOST}"
    echo "System Internal IP: ${INTERNAL_SERVER_HOST}"
    echo "Linux Username: ${LINUX_USERNAME}"
    echo "Linux Password: ${LINUX_PASSWORD}"
    echo "SSH Public Key: $(cat "${PUBLIC_SSH_KEY}")"
    echo "SSH Private Key: $(cat "${PRIVATE_SSH_KEY}")"
    echo "GPG Public Key: $(cat "${PUBLIC_GPG_KEY}")"
    echo "GPG Private Key: $(cat "${PRIVATE_GPG_KEY}")"
    echo "GPG Passphrase: ${GPG_LINUX_PASSWORD}"
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

#!/bin/bash
# DexterEskalarte V2Ray Premium Script
# For Donations, Im accepting prepaid loads or GCash transactions:
# Smart: 09614817656
# Facebook: https://www.facebook.com/profile.php?id=100008810621324

#############################
#############################
# Variables (Can be changed depends on your preferred values)

# Script name
MyScriptName='Mediatek-V2Ray'

# export DAT_PATH='/usr/local/share/v2ray'
DAT_PATH=${DAT_PATH:-/usr/local/share/v2ray}

# export JSON_PATH='/usr/local/etc/v2ray'
JSON_PATH=${JSON_PATH:-/usr/local/etc/v2ray}

# Your SSH Banner
SSH_Banner='https://raw.githubusercontent.com/hunt3rXhunt3r/dexter/master/issue.net'

# Server local time
MyVPS_Time='Asia/Manila'
#############################


#############################
#############################
## All function used for this script
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

function InstAsk(){
 clear
 echo "###############################################################"
 echo "#                         V2RAY Script                        #"
 echo "#                        By: Dexter Eskalarte                      #"
 echo "#                     [GCASH] 09614817656                    #"
 echo "###############################################################"
 echo ""
 echo "*IMPORTANT* PLEASE DONT SKIP"
 echo "1. Go you your cloudflare account"
 echo "2. Point A record domain on your VPS IP Address"
 echo "3. After pointing domain set TLS/SSL to Full."
 echo "4. Create ECDSA Origin Certificate on Cloudflare"
 echo "5. Upload your Origin Cert and Private key to Github or Cl1p.net"
 echo "6. Copy the links then put them here in the installer"
 read -p "Domain Link: " -e -i sample.dextereskalarte.tech MyDomain
 read -p "Certificate Link: " -e -i yourcertlink CertURL
 read -p "Private Key Link: " -e -i yourkeylink KeyURL
 echo ""
 echo "Great! That's all I need. We are ready to setup your v2ray with websocket now"
 read -n1 -r -p "Press any key to continue..."
}

function InstPassword(){
read -p "Enter Script Password: " pwd
if test $pwd == "mediatekv2ray"; then
echo "Password Accepted!"
else
echo "Password Incorrect!"
rm v2r*
sleep 2
exit
fi
}

function InstXray(){
echo "*INSTALLING* XRay Core (Along with V2Ray)"
echo ""
read -p "Continue? (y/n): " ans
if test $ans == "y"; then
echo "Continuing installation...."
sleep 2
wget https://raw.githubusercontent.com/hunt3rXhunt3r/dexter/master/install-xray.sh
else
echo "XRay Core will not be installed."
sleep 5
echo "FINISHING SETUP.!"
sleep 5
exit
fi
}

function SetBanner(){
 # Install BashRC Banner
apt-get install figlet
apt-get install cowsay fortune-mod -y
ln -s /usr/games/cowsay /bin
ln -s /usr/games/fortune /bin
echo "clear" >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'cowsay -f dragon "WELCOME MY BOSS." | lolcat' >> .bashrc
echo 'figlet -k Dexter Eskalarte' >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'echo -e "     =========================================================" | lolcat' >> .bashrc
echo 'echo -e "     *              WELCOME TO V2RAY | XRay SERVER           *" | lolcat' >> .bashrc
echo 'echo -e "     =========================================================" | lolcat' >> .bashrc
echo 'echo -e "     *                 Autoscript By Dexter Eskalarte              *" | lolcat' >> .bashrc
echo 'echo -e "     *                  Debian 9, 10 & Ubuntu18              *" | lolcat' >> .bashrc
echo 'echo -e "     *                   Facebook: Mediatek VPN               *" | lolcat' >> .bashrc
echo 'echo -e "     =========================================================" | lolcat' >> .bashrc
echo 'echo -e "     *             For Donations [GCASH] 09614817656         *"' >> .bashrc
echo 'echo -e "     =========================================================" | lolcat' >> .bashrc
echo 'echo -e "     Command [XRay Menu]: xmenu" | lolcat' >> .bashrc
echo 'echo -e "     Command [V2Ray Menu]: vmenu" | lolcat' >> .bashrc
echo 'echo -e ""' >> .bashrc

}

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 
 # Removing some firewall tools that may affect other services
 apt-get remove --purge ufw firewalld -y
 
 # Installing some important machine essentials
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc dropbear jq git openssl cron net-tools dnsutils dos2unix screen bzip2 psmisc lsof ccrypt -y
 
 # Now installing all our wanted services
 apt-get install gnupg tcpdump grepcidr screen ca-certificates nginx ruby apt-transport-https lsb-release -y
 
 # Installing a text colorizer
 gem install lolcat
 
 # Trying to remove obsolette packages after installation
 apt-get autoremove -y
 
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port 22
Port 143
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
Compression yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/jftvban
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Download our SSH Banner
 rm -f /etc/banner
 rm -f /etc/jftvban
 wget -qO /etc/jftvban "$SSH_Banner"
 dos2unix -q /etc/jftvban

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/bin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/bin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=550
DROPBEAR_EXTRA_ARGS="-p 445"
DROPBEAR_BANNER="/etc/jftvban"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InstWebsocket(){
 # Making UUID as Variable
 MyUUID=$(v2ctl uuid);
 
 # Deleting Obsolete NginX files and killing service
 rm -rf /etc/nginx/{default.d,conf.d/default.conf,sites-*}
 for PORT in "80" "443"; do { [ ! -z "$(lsof -ti:${PORT} -s tcp:listen)" ] && kill $(lsof -ti:${PORT}); }; done
 
 
 # Pulling NginX and V2ray Configs
 curl -kL "https://raw.githubusercontent.com/hunt3rXhunt3r/dexter/master/config.json" -o /usr/local/etc/v2ray/config.json
 curl -kL "https://raw.githubusercontent.com/hunt3rXhunt3r/dexter/master/v2ray.conf" -o /etc/nginx/conf.d/v2ray.conf
 
 # Using sed to change values on configs
 sed -i "s|SERVER_DOMAIN|$MyDomain|g;s|GENERATED_UUID_CODE|$MyUUID|g" /usr/local/etc/v2ray/config.json
 sed -i "s|DOMAIN_HERE|$MyDomain|g" /etc/nginx/conf.d/v2ray.conf
 
 # Pulling Cloudflare Origin Cert and Private Key
 curl -kL "$CertURL" -o /usr/local/etc/v2ray/cert.pem
 curl -kL "$KeyURL" -o /usr/local/etc/v2ray/key.pem
 curl -kL "https://support.cloudflare.com/hc/article_attachments/360037898732/origin_ca_ecc_root.pem" -o /usr/local/etc/v2ray/root_ecc.pem
 
 # Making Fullchain Pem Key
 printf "%b\n" "$(cat /usr/local/etc/v2ray/cert.pem)\n$(cat /usr/local/etc/v2ray/cert.pem)\n$(cat /usr/local/etc/v2ray/root_ecc.pem)" > /usr/local/etc/v2ray/fullchain.pem
 
 
 # Starting and Enabling Websocket and V2ray
 systemctl start v2ray &>/dev/null
 systemctl enable v2ray
 systemctl restart nginx
 
 # Adding XMENU and VMENU to system to provide UUID menu
 wget -O /usr/local/sbin/xmenu https://raw.githubusercontent.com/hunt3rXhunt3r/dexter/master/xmenu
 wget -O /usr/local/sbin/vmenu https://raw.githubusercontent.com/hunt3rXhunt3r/dexter/master/vmenu
 chmod +x /usr/local/sbin/xmenu
 chmod +x /usr/local/sbin/vmenu
 
}

function InstV2ray(){

# Start Installing V2ray by V2fly (JohnFordTV Fork)
curl() {
  $(type -P curl) -L -q --retry 5 --retry-delay 10 --retry-max-time 60 "$@"
}

systemd_cat_config() {
  if systemd-analyze --help | grep -qw 'cat-config'; then
    systemd-analyze --no-pager cat-config "$@"
    echo
  else
    echo "${aoi}~~~~~~~~~~~~~~~~"
    cat "$@" "$1".d/*
    echo "${aoi}~~~~~~~~~~~~~~~~"
    echo "${red}NOTICE: ${green}The systemd version on the current operating system is too low."
    echo "${red}NOTICE: ${green}Disregard this message if you are using Debian 10 or 9.${reset}"
    echo
  fi
}

check_if_running_as_root() {
  # If you want to run as another user, please modify $UID to be owned by this user
  if [[ "$UID" -ne '0' ]]; then
    echo "WARNING: The user currently executing this script is not root. You may encounter the insufficient privilege error."
    read -r -p "Are you sure you want to continue? [y/n] " cont_without_been_root
    if [[ x"${cont_without_been_root:0:1}" = x'y' ]]; then
      echo "Continuing the installation with current user..."
    else
      echo "Not running with root, exiting..."
      exit 1
    fi
  fi
}

identify_the_operating_system_and_architecture() {
  if [[ "$(uname)" == 'Linux' ]]; then
    case "$(uname -m)" in
      'i386' | 'i686')
        MACHINE='32'
        ;;
      'amd64' | 'x86_64')
        MACHINE='64'
        ;;
      'armv5tel')
        MACHINE='arm32-v5'
        ;;
      'armv6l')
        MACHINE='arm32-v6'
        grep Features /proc/cpuinfo | grep -qw 'vfp' || MACHINE='arm32-v5'
        ;;
      'armv7' | 'armv7l')
        MACHINE='arm32-v7a'
        grep Features /proc/cpuinfo | grep -qw 'vfp' || MACHINE='arm32-v5'
        ;;
      'armv8' | 'aarch64')
        MACHINE='arm64-v8a'
        ;;
      'mips')
        MACHINE='mips32'
        ;;
      'mipsle')
        MACHINE='mips32le'
        ;;
      'mips64')
        MACHINE='mips64'
        ;;
      'mips64le')
        MACHINE='mips64le'
        ;;
      'ppc64')
        MACHINE='ppc64'
        ;;
      'ppc64le')
        MACHINE='ppc64le'
        ;;
      'riscv64')
        MACHINE='riscv64'
        ;;
      's390x')
        MACHINE='s390x'
        ;;
      *)
        echo "error: The architecture is not supported."
        exit 1
        ;;
    esac
    if [[ ! -f '/etc/os-release' ]]; then
      echo "error: Don't use outdated Linux distributions."
      exit 1
    fi
    # Do not combine this judgment condition with the following judgment condition.
    ## Be aware of Linux distribution like Gentoo, which kernel supports switch between Systemd and OpenRC.
    ### Refer: https://github.com/v2fly/fhs-install-v2ray/issues/84#issuecomment-688574989
    if [[ -f /.dockerenv ]] || grep -q 'docker\|lxc' /proc/1/cgroup && [[ "$(type -P systemctl)" ]]; then
      true
    elif [[ -d /run/systemd/system ]] || grep -q systemd <(ls -l /sbin/init); then
      true
    else
      echo "error: Only Linux distributions using systemd are supported."
      exit 1
    fi
    if [[ "$(type -P apt)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='apt -y --no-install-recommends install'
      PACKAGE_MANAGEMENT_REMOVE='apt purge'
      package_provide_tput='ncurses-bin'
    elif [[ "$(type -P dnf)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='dnf -y install'
      PACKAGE_MANAGEMENT_REMOVE='dnf remove'
      package_provide_tput='ncurses'
    elif [[ "$(type -P yum)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='yum -y install'
      PACKAGE_MANAGEMENT_REMOVE='yum remove'
      package_provide_tput='ncurses'
    elif [[ "$(type -P zypper)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='zypper install -y --no-recommends'
      PACKAGE_MANAGEMENT_REMOVE='zypper remove'
      package_provide_tput='ncurses-utils'
    elif [[ "$(type -P pacman)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='pacman -Syu --noconfirm'
      PACKAGE_MANAGEMENT_REMOVE='pacman -Rsn'
      package_provide_tput='ncurses'
    else
      echo "error: The script does not support the package manager in this operating system."
      exit 1
    fi
  else
    echo "error: This operating system is not supported."
    exit 1
  fi
}

## Demo function for processing parameters
judgment_parameters() {
  while [[ "$#" -gt '0' ]]; do
    case "$1" in
      '--remove')
        if [[ "$#" -gt '1' ]]; then
          echo 'error: Please enter the correct parameters.'
          exit 1
        fi
        REMOVE='1'
        ;;
      '--version')
        VERSION="${2:?error: Please specify the correct version.}"
        break
        ;;
      '-c' | '--check')
        CHECK='1'
        break
        ;;
      '-f' | '--force')
        FORCE='1'
        break
        ;;
      '-h' | '--help')
        HELP='1'
        break
        ;;
      '-l' | '--local')
        LOCAL_INSTALL='1'
        LOCAL_FILE="${2:?error: Please specify the correct local file.}"
        break
        ;;
      '-p' | '--proxy')
        if [[ -z "${2:?error: Please specify the proxy server address.}" ]]; then
          exit 1
        fi
        PROXY="$2"
        shift
        ;;
      *)
        echo "$0: unknown option -- -"
        exit 1
        ;;
    esac
    shift
  done
}

install_software() {
  package_name="$1"
  file_to_detect="$2"
  type -P "$file_to_detect" > /dev/null 2>&1 && return
  if ${PACKAGE_MANAGEMENT_INSTALL} "$package_name"; then
    echo "info: $package_name is installed."
  else
    echo "error: Installation of $package_name failed, please check your network."
    exit 1
  fi
}

get_version() {
  # 0: Install or update V2Ray.
  # 1: Installed or no new version of V2Ray.
  # 2: Install the specified version of V2Ray.
  if [[ -n "$VERSION" ]]; then
    RELEASE_VERSION="v${VERSION#v}"
    return 2
  fi
  # Determine the version number for V2Ray installed from a local file
  if [[ -f '/usr/local/bin/v2ray' ]]; then
    VERSION="$(/usr/local/bin/v2ray -version | awk 'NR==1 {print $2}')"
    CURRENT_VERSION="v${VERSION#v}"
    if [[ "$LOCAL_INSTALL" -eq '1' ]]; then
      RELEASE_VERSION="$CURRENT_VERSION"
      return
    fi
  fi
  # Get V2Ray release version number
  TMP_FILE="$(mktemp)"
  if ! curl -x "${PROXY}" -sS -H "Accept: application/vnd.github.v3+json" -o "$TMP_FILE" 'https://api.github.com/repos/v2fly/v2ray-core/releases/latest'; then
    "rm" "$TMP_FILE"
    echo 'error: Failed to get release list, please check your network.'
    exit 1
  fi
  RELEASE_LATEST="$(sed 'y/,/\n/' "$TMP_FILE" | grep 'tag_name' | awk -F '"' '{print $4}')"
  "rm" "$TMP_FILE"
  RELEASE_VERSION="v${RELEASE_LATEST#v}"
  # Compare V2Ray version numbers
  if [[ "$RELEASE_VERSION" != "$CURRENT_VERSION" ]]; then
    RELEASE_VERSIONSION_NUMBER="${RELEASE_VERSION#v}"
    RELEASE_MAJOR_VERSION_NUMBER="${RELEASE_VERSIONSION_NUMBER%%.*}"
    RELEASE_MINOR_VERSION_NUMBER="$(echo "$RELEASE_VERSIONSION_NUMBER" | awk -F '.' '{print $2}')"
    RELEASE_MINIMUM_VERSION_NUMBER="${RELEASE_VERSIONSION_NUMBER##*.}"
    # shellcheck disable=SC2001
    CURRENT_VERSIONSION_NUMBER="$(echo "${CURRENT_VERSION#v}" | sed 's/-.*//')"
    CURRENT_MAJOR_VERSION_NUMBER="${CURRENT_VERSIONSION_NUMBER%%.*}"
    CURRENT_MINOR_VERSION_NUMBER="$(echo "$CURRENT_VERSIONSION_NUMBER" | awk -F '.' '{print $2}')"
    CURRENT_MINIMUM_VERSION_NUMBER="${CURRENT_VERSIONSION_NUMBER##*.}"
    if [[ "$RELEASE_MAJOR_VERSION_NUMBER" -gt "$CURRENT_MAJOR_VERSION_NUMBER" ]]; then
      return 0
    elif [[ "$RELEASE_MAJOR_VERSION_NUMBER" -eq "$CURRENT_MAJOR_VERSION_NUMBER" ]]; then
      if [[ "$RELEASE_MINOR_VERSION_NUMBER" -gt "$CURRENT_MINOR_VERSION_NUMBER" ]]; then
        return 0
      elif [[ "$RELEASE_MINOR_VERSION_NUMBER" -eq "$CURRENT_MINOR_VERSION_NUMBER" ]]; then
        if [[ "$RELEASE_MINIMUM_VERSION_NUMBER" -gt "$CURRENT_MINIMUM_VERSION_NUMBER" ]]; then
          return 0
        else
          return 1
        fi
      else
        return 1
      fi
    else
      return 1
    fi
  elif [[ "$RELEASE_VERSION" == "$CURRENT_VERSION" ]]; then
    return 1
  fi
}

download_v2ray() {
  DOWNLOAD_LINK="https://github.com/v2fly/v2ray-core/releases/download/$RELEASE_VERSION/v2ray-linux-$MACHINE.zip"
  echo "Downloading V2Ray archive: $DOWNLOAD_LINK"
  if ! curl -x "${PROXY}" -R -H 'Cache-Control: no-cache' -o "$ZIP_FILE" "$DOWNLOAD_LINK"; then
    echo 'error: Download failed! Please check your network or try again.'
    return 1
  fi
  echo "Downloading verification file for V2Ray archive: $DOWNLOAD_LINK.dgst"
  if ! curl -x "${PROXY}" -sSR -H 'Cache-Control: no-cache' -o "$ZIP_FILE.dgst" "$DOWNLOAD_LINK.dgst"; then
    echo 'error: Download failed! Please check your network or try again.'
    return 1
  fi
  if [[ "$(cat "$ZIP_FILE".dgst)" == 'Not Found' ]]; then
    echo 'error: This version does not support verification. Please replace with another version.'
    return 1
  fi

  # Verification of V2Ray archive
  for LISTSUM in 'md5' 'sha1' 'sha256' 'sha512'; do
    SUM="$(${LISTSUM}sum "$ZIP_FILE" | sed 's/ .*//')"
    CHECKSUM="$(grep ${LISTSUM^^} "$ZIP_FILE".dgst | grep "$SUM" -o -a | uniq)"
    if [[ "$SUM" != "$CHECKSUM" ]]; then
      echo 'error: Check failed! Please check your network or try again.'
      return 1
    fi
  done
}

decompression() {
  if ! unzip -q "$1" -d "$TMP_DIRECTORY"; then
    echo 'error: V2Ray decompression failed.'
    "rm" -r "$TMP_DIRECTORY"
    echo "removed: $TMP_DIRECTORY"
    exit 1
  fi
  echo "info: Extract the V2Ray package to $TMP_DIRECTORY and prepare it for installation."
}

install_file() {
  NAME="$1"
  if [[ "$NAME" == 'v2ray' ]] || [[ "$NAME" == 'v2ctl' ]]; then
    install -m 755 "${TMP_DIRECTORY}/$NAME" "/usr/local/bin/$NAME"
  elif [[ "$NAME" == 'geoip.dat' ]] || [[ "$NAME" == 'geosite.dat' ]]; then
    install -m 644 "${TMP_DIRECTORY}/$NAME" "${DAT_PATH}/$NAME"
  fi
}

install_v2ray() {
  # Install V2Ray binary to /usr/local/bin/ and $DAT_PATH
  install_file v2ray
  install_file v2ctl
  install -d "$DAT_PATH"
  # If the file exists, geoip.dat and geosite.dat will not be installed or updated
  if [[ ! -f "${DAT_PATH}/.undat" ]]; then
    install_file geoip.dat
    install_file geosite.dat
  fi

  # Install V2Ray configuration file to $JSON_PATH
  # shellcheck disable=SC2153
  if [[ -z "$JSONS_PATH" ]] && [[ ! -d "$JSON_PATH" ]]; then
    install -d "$JSON_PATH"
    echo "{}" > "${JSON_PATH}/config.json"
    CONFIG_NEW='1'
  fi

  # Install V2Ray configuration file to $JSONS_PATH
  if [[ -n "$JSONS_PATH" ]] && [[ ! -d "$JSONS_PATH" ]]; then
    install -d "$JSONS_PATH"
    for BASE in 00_log 01_api 02_dns 03_routing 04_policy 05_inbounds 06_outbounds 07_transport 08_stats 09_reverse; do
      echo '{}' > "${JSONS_PATH}/${BASE}.json"
    done
    CONFDIR='1'
  fi

  # Used to store V2Ray log files
  if [[ ! -d '/var/log/v2ray/' ]]; then
    if id nobody | grep -qw 'nogroup'; then
      install -d -m 700 -o nobody -g nogroup /var/log/v2ray/
      install -m 600 -o nobody -g nogroup /dev/null /var/log/v2ray/access.log
      install -m 600 -o nobody -g nogroup /dev/null /var/log/v2ray/error.log
    else
      install -d -m 700 -o nobody -g nobody /var/log/v2ray/
      install -m 600 -o nobody -g nobody /dev/null /var/log/v2ray/access.log
      install -m 600 -o nobody -g nobody /dev/null /var/log/v2ray/error.log
    fi
    LOG='1'
  fi
}

install_startup_service_file() {
  install -m 644 "${TMP_DIRECTORY}/systemd/system/v2ray.service" /etc/systemd/system/v2ray.service
  install -m 644 "${TMP_DIRECTORY}/systemd/system/v2ray@.service" /etc/systemd/system/v2ray@.service
  mkdir -p '/etc/systemd/system/v2ray.service.d'
  mkdir -p '/etc/systemd/system/v2ray@.service.d/'
  if [[ -n "$JSONS_PATH" ]]; then
    "rm" '/etc/systemd/system/v2ray.service.d/10-donot_touch_single_conf.conf' \
      '/etc/systemd/system/v2ray@.service.d/10-donot_touch_single_conf.conf'
    echo "# In case you have a good reason to do so, duplicate this file in the same directory and make your customizes there.
# Or all changes you made will be lost!  # Refer: https://www.freedesktop.org/software/systemd/man/systemd.unit.html
[Service]
ExecStart=
ExecStart=/usr/local/bin/v2ray -confdir $JSONS_PATH" |
      tee '/etc/systemd/system/v2ray.service.d/10-donot_touch_multi_conf.conf' > \
        '/etc/systemd/system/v2ray@.service.d/10-donot_touch_multi_conf.conf'
  else
    "rm" '/etc/systemd/system/v2ray.service.d/10-donot_touch_multi_conf.conf' \
      '/etc/systemd/system/v2ray@.service.d/10-donot_touch_multi_conf.conf'
    echo "# In case you have a good reason to do so, duplicate this file in the same directory and make your customizes there.
# Or all changes you made will be lost!  # Refer: https://www.freedesktop.org/software/systemd/man/systemd.unit.html
[Service]
ExecStart=
ExecStart=/usr/local/bin/v2ray -config ${JSON_PATH}/config.json" > \
      '/etc/systemd/system/v2ray.service.d/10-donot_touch_single_conf.conf'
    echo "# In case you have a good reason to do so, duplicate this file in the same directory and make your customizes there.
# Or all changes you made will be lost!  # Refer: https://www.freedesktop.org/software/systemd/man/systemd.unit.html
[Service]
ExecStart=
ExecStart=/usr/local/bin/v2ray -config ${JSON_PATH}/%i.json" > \
      '/etc/systemd/system/v2ray@.service.d/10-donot_touch_single_conf.conf'
  fi
  echo "info: Systemd service files have been installed successfully!"
  echo "${red}warning: ${green}The following are the actual parameters for the v2ray service startup."
  echo "${red}warning: ${green}Please make sure the configuration file path is correctly set.${reset}"
  systemd_cat_config /etc/systemd/system/v2ray.service
  # shellcheck disable=SC2154
  if [[ x"${check_all_service_files:0:1}" = x'y' ]]; then
    echo
    echo
    systemd_cat_config /etc/systemd/system/v2ray@.service
  fi
  systemctl daemon-reload
  SYSTEMD='1'
}

start_v2ray() {
  if [[ -f '/etc/systemd/system/v2ray.service' ]]; then
    if systemctl start "${V2RAY_CUSTOMIZE:-v2ray}"; then
      echo 'info: Start the V2Ray service.'
    else
      echo 'error: Failed to start V2Ray service.'
      exit 1
    fi
  fi
}

stop_v2ray() {
  V2RAY_CUSTOMIZE="$(systemctl list-units | grep 'v2ray@' | awk -F ' ' '{print $1}')"
  if [[ -z "$V2RAY_CUSTOMIZE" ]]; then
    local v2ray_daemon_to_stop='v2ray.service'
  else
    local v2ray_daemon_to_stop="$V2RAY_CUSTOMIZE"
  fi
  if ! systemctl stop "$v2ray_daemon_to_stop"; then
    echo 'error: Stopping the V2Ray service failed.'
    exit 1
  fi
  echo 'info: Stop the V2Ray service.'
}

check_update() {
  if [[ -f '/etc/systemd/system/v2ray.service' ]]; then
    get_version
    local get_ver_exit_code=$?
    if [[ "$get_ver_exit_code" -eq '0' ]]; then
      echo "info: Found the latest release of V2Ray $RELEASE_VERSION . (Current release: $CURRENT_VERSION)"
    elif [[ "$get_ver_exit_code" -eq '1' ]]; then
      echo "info: No new version. The current version of V2Ray is $CURRENT_VERSION ."
    fi
    exit 0
  else
    echo 'error: V2Ray is not installed.'
    exit 1
  fi
}

remove_v2ray() {
  if systemctl list-unit-files | grep -qw 'v2ray'; then
    if [[ -n "$(pidof v2ray)" ]]; then
      stop_v2ray
    fi
    if ! ("rm" -r '/usr/local/bin/v2ray' \
      '/usr/local/bin/v2ctl' \
      "$DAT_PATH" \
      '/etc/systemd/system/v2ray.service' \
      '/etc/systemd/system/v2ray@.service' \
      '/etc/systemd/system/v2ray.service.d' \
      '/etc/systemd/system/v2ray@.service.d'); then
      echo 'error: Failed to remove V2Ray.'
      exit 1
    else
      echo 'removed: /usr/local/bin/v2ray'
      echo 'removed: /usr/local/bin/v2ctl'
      echo "removed: $DAT_PATH"
      echo 'removed: /etc/systemd/system/v2ray.service'
      echo 'removed: /etc/systemd/system/v2ray@.service'
      echo 'removed: /etc/systemd/system/v2ray.service.d'
      echo 'removed: /etc/systemd/system/v2ray@.service.d'
      echo 'Please execute the command: systemctl disable v2ray'
      echo "You may need to execute a command to remove dependent software: $PACKAGE_MANAGEMENT_REMOVE curl unzip"
      echo 'info: V2Ray has been removed.'
      echo 'info: If necessary, manually delete the configuration and log files.'
      if [[ -n "$JSONS_PATH" ]]; then
        echo "info: e.g., $JSONS_PATH and /var/log/v2ray/ ..."
      else
        echo "info: e.g., $JSON_PATH and /var/log/v2ray/ ..."
      fi
      exit 0
    fi
  else
    echo 'error: V2Ray is not installed.'
    exit 1
  fi
}

# Explanation of parameters in the script
show_help() {
  echo "usage: $0 [--remove | --version number | -c | -f | -h | -l | -p]"
  echo '  [-p address] [--version number | -c | -f]'
  echo '  --remove        Remove V2Ray'
  echo '  --version       Install the specified version of V2Ray, e.g., --version v4.18.0'
  echo '  -c, --check     Check if V2Ray can be updated'
  echo '  -f, --force     Force installation of the latest version of V2Ray'
  echo '  -h, --help      Show help'
  echo '  -l, --local     Install V2Ray from a local file'
  echo '  -p, --proxy     Download through a proxy server, e.g., -p http://127.0.0.1:8118 or -p socks5://127.0.0.1:1080'
  exit 0
}

installnow() {
  check_if_running_as_root
  identify_the_operating_system_and_architecture
  judgment_parameters "$@"

  install_software "$package_provide_tput" 'tput'
  red=$(tput setaf 1)
  green=$(tput setaf 2)
  aoi=$(tput setaf 6)
  reset=$(tput sgr0)

  # Parameter information
  [[ "$HELP" -eq '1' ]] && show_help
  [[ "$CHECK" -eq '1' ]] && check_update
  [[ "$REMOVE" -eq '1' ]] && remove_v2ray

  # Two very important variables
  TMP_DIRECTORY="$(mktemp -d)"
  ZIP_FILE="${TMP_DIRECTORY}/v2ray-linux-$MACHINE.zip"

  # Install V2Ray from a local file, but still need to make sure the network is available
  if [[ "$LOCAL_INSTALL" -eq '1' ]]; then
    echo 'warn: Install V2Ray from a local file, but still need to make sure the network is available.'
    echo -n 'warn: Please make sure the file is valid because we cannot confirm it. (Press any key) ...'
    read -r
    install_software 'unzip' 'unzip'
    decompression "$LOCAL_FILE"
  else
    # Normal way
    install_software 'curl' 'curl'
    get_version
    NUMBER="$?"
    if [[ "$NUMBER" -eq '0' ]] || [[ "$FORCE" -eq '1' ]] || [[ "$NUMBER" -eq 2 ]]; then
      echo "info: Installing V2Ray $RELEASE_VERSION for $(uname -m)"
      download_v2ray
      if [[ "$?" -eq '1' ]]; then
        "rm" -r "$TMP_DIRECTORY"
        echo "removed: $TMP_DIRECTORY"
        exit 1
      fi
      install_software 'unzip' 'unzip'
      decompression "$ZIP_FILE"
    elif [[ "$NUMBER" -eq '1' ]]; then
      echo "info: No new version. The current version of V2Ray is $CURRENT_VERSION ."
      exit 0
    fi
  fi

  # Determine if V2Ray is running
  if systemctl list-unit-files | grep -qw 'v2ray'; then
    if [[ -n "$(pidof v2ray)" ]]; then
      stop_v2ray
      V2RAY_RUNNING='1'
    fi
  fi
  install_v2ray
  install_startup_service_file
  echo 'installed: /usr/local/bin/v2ray'
  echo 'installed: /usr/local/bin/v2ctl'
  # If the file exists, the content output of installing or updating geoip.dat and geosite.dat will not be displayed
  if [[ ! -f "${DAT_PATH}/.undat" ]]; then
    echo "installed: ${DAT_PATH}/geoip.dat"
    echo "installed: ${DAT_PATH}/geosite.dat"
  fi
  if [[ "$CONFIG_NEW" -eq '1' ]]; then
    echo "installed: ${JSON_PATH}/config.json"
  fi
  if [[ "$CONFDIR" -eq '1' ]]; then
    echo "installed: ${JSON_PATH}/00_log.json"
    echo "installed: ${JSON_PATH}/01_api.json"
    echo "installed: ${JSON_PATH}/02_dns.json"
    echo "installed: ${JSON_PATH}/03_routing.json"
    echo "installed: ${JSON_PATH}/04_policy.json"
    echo "installed: ${JSON_PATH}/05_inbounds.json"
    echo "installed: ${JSON_PATH}/06_outbounds.json"
    echo "installed: ${JSON_PATH}/07_transport.json"
    echo "installed: ${JSON_PATH}/08_stats.json"
    echo "installed: ${JSON_PATH}/09_reverse.json"
  fi
  if [[ "$LOG" -eq '1' ]]; then
    echo 'installed: /var/log/v2ray/'
    echo 'installed: /var/log/v2ray/access.log'
    echo 'installed: /var/log/v2ray/error.log'
  fi
  if [[ "$SYSTEMD" -eq '1' ]]; then
    echo 'installed: /etc/systemd/system/v2ray.service'
    echo 'installed: /etc/systemd/system/v2ray@.service'
  fi
  "rm" -r "$TMP_DIRECTORY"
  echo "removed: $TMP_DIRECTORY"
  if [[ "$LOCAL_INSTALL" -eq '1' ]]; then
    get_version
  fi
  echo "info: V2Ray $RELEASE_VERSION is installed."
  echo "You may need to execute a command to remove dependent software: $PACKAGE_MANAGEMENT_REMOVE curl unzip"
  if [[ "$V2RAY_RUNNING" -eq '1' ]]; then
    start_v2ray
  else
    echo 'Please execute the command: systemctl enable v2ray; systemctl start v2ray'
	echo 'WAIT UNTIL JOHNFORDTV SCRIPT FINISHED'
  fi
}

installnow "$@"
}

function ScriptMessage(){
 echo -e " $MyScriptName"  | lolcat
 echo -e ""
 echo -e " https://www.facebook.com/profile.php?id=100008810621324"
 echo -e "[GCASH] 09614817656 [PAYONEER] admin@dextereskalarte.tech"
 echo -e ""
}


 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 InstPassword
 sleep 1
 InstAsk
 InstUpdates
 ScriptMessage
 sleep 10
 
  # Configure OpenSSH and Dropbear
 echo -e "Configuring Server... " | lolcat
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring V2ray... " | lolcat
 InstV2ray
 
 # Configure Webmin
 echo -e "Configuring WebSocket... " | lolcat
 InstWebsocket
 
 # Configure NginX
 echo -e "Configuring NginX... " | lolcat
 SetBanner

 clear
 cd ~
 
 # Showing script's banner message
 ScriptMessage
 sleep 10
 InstXray
 
  # Showing additional information from installating this script
echo " "
echo "The server is 100% installed. Please read the server rules and reboot your VPS!"
echo " "
echo "--------------------------------------------------------------------------------"
echo "*                            Debian Premium Script                             *"
echo "*                                 -DexterEskalarte-                                 *"
echo "--------------------------------------------------------------------------------"
echo "-----------------------"  | tee -a log-install.txt
echo "Premium Script Information"  | tee -a log-install.txt
echo "-----------------------"  | tee -a log-install.txt
echo "DONATION:"  | tee -a log-install.txt
echo "GCASH: 09614817656"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Developed:"  | tee -a log-install.txt
echo "©JohnFordTV"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "------------------------------- REBOOT YOUR VPS! -------------------------------"

 # Clearing all logs from installation
rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
rm -f v2r*
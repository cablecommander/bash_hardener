#!/bin/bash

###############################################################################
# Ubuntu Server Hardening Script
# This script hardens an Ubuntu server by:
# - Configuring automatic updates
# - Changing SSH port to 555
# - Disabling root SSH login
# - Enabling UFW firewall
# - Configuring Fail2Ban for SSH protection
# - Joining Windows Active Directory domain (optional)
# - Allowing custom ports
###############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Function to check if command succeeded
check_error() {
    if [ $? -ne 0 ]; then
        print_error "$1"
        exit 1
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

print_info "==================================================================="
print_info "Ubuntu Server Hardening Script"
print_info "==================================================================="
echo ""

###############################################################################
# 1. Configure Automatic Updates
###############################################################################

print_info "Configuring automatic updates..."
echo ""
echo "Please select your automatic update preference:"
echo "1) Only security updates auto-install"
echo "2) All updates auto-install"
echo "3) Auto-download but manual install"
echo "4) Disable auto-updates"
echo ""
read -p "Enter your choice (1-4): " update_choice

case $update_choice in
    1)
        print_info "Configuring security updates only..."
        apt-get update -qq
        check_error "Failed to update package lists"

        apt-get install -y unattended-upgrades apt-listchanges
        check_error "Failed to install unattended-upgrades package"

        cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
        check_error "Failed to configure unattended-upgrades"

        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
        check_error "Failed to enable automatic updates"
        print_success "Security updates configured successfully"
        ;;
    2)
        print_info "Configuring all updates to auto-install..."
        apt-get update -qq
        check_error "Failed to update package lists"

        apt-get install -y unattended-upgrades apt-listchanges
        check_error "Failed to install unattended-upgrades package"

        cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
        check_error "Failed to configure unattended-upgrades"

        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
        check_error "Failed to enable automatic updates"
        print_success "All updates configured to auto-install successfully"
        ;;
    3)
        print_info "Configuring auto-download with manual install..."
        apt-get update -qq
        check_error "Failed to update package lists"

        apt-get install -y unattended-upgrades apt-listchanges
        check_error "Failed to install unattended-upgrades package"

        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "0";
EOF
        check_error "Failed to configure auto-download"
        print_success "Auto-download configured successfully (manual install required)"
        ;;
    4)
        print_info "Disabling auto-updates..."
        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
        check_error "Failed to disable auto-updates"
        print_success "Auto-updates disabled"
        ;;
    *)
        print_error "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""

###############################################################################
# 2. Configure SSH - Change Port and Disable Root Login
###############################################################################

print_info "Configuring SSH settings..."

# Check if SSH is installed
if ! command -v sshd &> /dev/null; then
    print_error "OpenSSH server is not installed. Installing..."
    apt-get install -y openssh-server
    check_error "Failed to install OpenSSH server"
fi

# Verify SSH config file exists
if [ ! -f /etc/ssh/sshd_config ]; then
    print_error "SSH configuration file not found at /etc/ssh/sshd_config"
    exit 1
fi

# Change SSH port to 555
print_info "Changing SSH port to 555..."
sed -i 's/^#\?Port .*/Port 555/' /etc/ssh/sshd_config
check_error "Failed to change SSH port"

# Verify port change
if grep -q "^Port 555" /etc/ssh/sshd_config; then
    print_success "SSH port changed to 555"
else
    print_error "Failed to verify SSH port change"
    exit 1
fi

# Disable root login
print_info "Disabling root SSH login..."
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
check_error "Failed to disable root login"

# Verify root login disabled
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
    print_success "Root SSH login disabled"
else
    print_error "Failed to verify root login disabled"
    exit 1
fi

# Test SSH configuration
print_info "Testing SSH configuration..."
sshd -t
check_error "SSH configuration test failed. Please check /etc/ssh/sshd_config"
print_success "SSH configuration is valid"

echo ""

###############################################################################
# 3. Configure UFW Firewall
###############################################################################

print_info "Configuring UFW firewall..."

# Install UFW if not present
if ! command -v ufw &> /dev/null; then
    print_info "UFW not found. Installing..."
    apt-get install -y ufw
    check_error "Failed to install UFW"
fi

# Reset UFW to default settings
print_info "Resetting UFW to default settings..."
ufw --force reset > /dev/null 2>&1

# Set default policies
print_info "Setting default firewall policies..."
ufw default deny incoming
check_error "Failed to set default incoming policy"

ufw default allow outgoing
check_error "Failed to set default outgoing policy"

# Allow SSH on port 555
print_info "Allowing SSH on port 555..."
ufw allow 555/tcp comment 'SSH'
check_error "Failed to allow port 555"
print_success "Port 555 (SSH) allowed through firewall"

echo ""

###############################################################################
# 4. Configure Fail2Ban for SSH Protection
###############################################################################

print_info "==================================================================="
print_info "Configuring Fail2Ban for SSH Protection"
print_info "==================================================================="
echo ""

# Install Fail2Ban
print_info "Installing Fail2Ban..."
apt-get install -y fail2ban
check_error "Failed to install Fail2Ban"
print_success "Fail2Ban installed successfully"

echo ""

# Detect current IP address
print_info "Detecting your current IP address..."
CURRENT_IP=$(echo $SSH_CONNECTION | awk '{print $1}')

# If SSH_CONNECTION is not available, try other methods
if [ -z "$CURRENT_IP" ]; then
    CURRENT_IP=$(who am i --ips 2>/dev/null | awk '{print $NF}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
fi

# If still no IP, try to get from last login
if [ -z "$CURRENT_IP" ]; then
    CURRENT_IP=$(last -i | grep "still logged in" | head -n 1 | awk '{print $3}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
fi

# Whitelist configuration
WHITELIST_IPS=()

if [ -n "$CURRENT_IP" ]; then
    print_info "Your current IP address appears to be: $CURRENT_IP"
    echo ""
    print_warning "STRONGLY RECOMMENDED: Whitelist your current IP to prevent lockout!"
    read -p "Do you want to whitelist $CURRENT_IP? (y/n): " whitelist_current

    if [[ "$whitelist_current" =~ ^[Yy]$ ]]; then
        WHITELIST_IPS+=("$CURRENT_IP")
        print_success "Added $CURRENT_IP to whitelist"
    else
        print_warning "Current IP NOT whitelisted - be careful with your login attempts!"
    fi
else
    print_warning "Could not detect your current IP address"
fi

echo ""
print_info "Would you like to add additional IPs to the whitelist?"
print_info "(Whitelisted IPs will NEVER be banned by Fail2Ban)"
read -p "Add more IPs to whitelist? (y/n): " add_more_ips

if [[ "$add_more_ips" =~ ^[Yy]$ ]]; then
    while true; do
        echo ""
        read -p "Enter IP address to whitelist (or 'done' to finish): " whitelist_ip

        if [[ "$whitelist_ip" == "done" ]]; then
            break
        fi

        # Validate IP address format
        if [[ $whitelist_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            WHITELIST_IPS+=("$whitelist_ip")
            print_success "Added $whitelist_ip to whitelist"
        else
            print_error "Invalid IP address format. Please try again."
        fi
    done
fi

# Show final warning if no whitelist
if [ ${#WHITELIST_IPS[@]} -eq 0 ]; then
    echo ""
    print_warning "==================================================================="
    print_warning "DANGER: NO IP WHITELIST CONFIGURED!"
    print_warning "==================================================================="
    print_warning "If you enter your password incorrectly 5 times, you will be"
    print_warning "PERMANENTLY LOCKED OUT and will need console access to recover!"
    print_warning "It is HIGHLY recommended to whitelist at least one IP address."
    echo ""
    read -p "Are you SURE you want to continue without a whitelist? (yes/no): " confirm_no_whitelist

    if [[ ! "$confirm_no_whitelist" == "yes" ]]; then
        print_info "Returning to whitelist configuration..."
        read -p "Enter at least one IP address to whitelist: " whitelist_ip
        if [[ $whitelist_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            WHITELIST_IPS+=("$whitelist_ip")
            print_success "Added $whitelist_ip to whitelist"
        else
            print_error "Invalid IP address. Exiting for safety."
            exit 1
        fi
    fi
fi

echo ""
print_info "Configuring Fail2Ban for SSH on port 555..."

# Create custom jail configuration
cat > /etc/fail2ban/jail.d/sshd-custom.conf << EOF
[sshd]
enabled = true
port = 555
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = -1
findtime = 600
action = iptables-multiport[name=SSH, port="555", protocol=tcp]
EOF

check_error "Failed to create Fail2Ban jail configuration"

# Add whitelist IPs to jail configuration if any
if [ ${#WHITELIST_IPS[@]} -gt 0 ]; then
    print_info "Adding ${#WHITELIST_IPS[@]} IP(s) to Fail2Ban whitelist..."
    IGNORE_IP_LINE="ignoreip = 127.0.0.1/8 ::1"

    for ip in "${WHITELIST_IPS[@]}"; do
        IGNORE_IP_LINE="$IGNORE_IP_LINE $ip"
    done

    # Add ignoreip line to jail config
    sed -i "/^\[sshd\]/a $IGNORE_IP_LINE" /etc/fail2ban/jail.d/sshd-custom.conf
    check_error "Failed to add whitelist IPs to Fail2Ban"

    print_success "Whitelisted IPs:"
    for ip in "${WHITELIST_IPS[@]}"; do
        print_success "  - $ip"
    done
fi

# Restart Fail2Ban to apply configuration
print_info "Restarting Fail2Ban service..."
systemctl restart fail2ban
check_error "Failed to restart Fail2Ban"

# Verify Fail2Ban is running
if systemctl is-active --quiet fail2ban; then
    print_success "Fail2Ban is running and monitoring SSH on port 555"
else
    print_error "Fail2Ban service is not running!"
    exit 1
fi

# Verify jail is active
sleep 2
if fail2ban-client status sshd &> /dev/null; then
    print_success "SSH jail is active and monitoring"
    echo ""
    print_info "Fail2Ban Configuration:"
    print_info "  - Monitoring: SSH port 555"
    print_info "  - Max retries: 5 failed attempts"
    print_info "  - Ban duration: PERMANENT"
    print_info "  - Time window: 10 minutes"
    if [ ${#WHITELIST_IPS[@]} -gt 0 ]; then
        print_info "  - Whitelisted IPs: ${#WHITELIST_IPS[@]}"
    fi
else
    print_warning "Could not verify SSH jail status, but service is running"
fi

echo ""

###############################################################################
# 5. Ask for Additional Ports
###############################################################################

print_info "Would you like to open any additional ports?"
read -p "Open additional ports? (y/n): " open_ports

if [[ "$open_ports" =~ ^[Yy]$ ]]; then
    while true; do
        echo ""
        read -p "Enter port number (or 'done' to finish): " port_num

        if [[ "$port_num" == "done" ]]; then
            break
        fi

        # Validate port number
        if ! [[ "$port_num" =~ ^[0-9]+$ ]] || [ "$port_num" -lt 1 ] || [ "$port_num" -gt 65535 ]; then
            print_error "Invalid port number. Please enter a number between 1 and 65535"
            continue
        fi

        read -p "Protocol (tcp/udp/both): " protocol
        protocol=$(echo "$protocol" | tr '[:upper:]' '[:lower:]')

        read -p "Description/Service name: " service_desc

        case $protocol in
            tcp)
                ufw allow $port_num/tcp comment "$service_desc"
                check_error "Failed to allow port $port_num/tcp"
                print_success "Port $port_num/tcp allowed for $service_desc"
                ;;
            udp)
                ufw allow $port_num/udp comment "$service_desc"
                check_error "Failed to allow port $port_num/udp"
                print_success "Port $port_num/udp allowed for $service_desc"
                ;;
            both)
                ufw allow $port_num/tcp comment "$service_desc"
                check_error "Failed to allow port $port_num/tcp"
                ufw allow $port_num/udp comment "$service_desc"
                check_error "Failed to allow port $port_num/udp"
                print_success "Port $port_num/tcp and udp allowed for $service_desc"
                ;;
            *)
                print_error "Invalid protocol. Skipping this port."
                continue
                ;;
        esac
    done
fi

# Enable UFW
print_info "Enabling UFW firewall..."
ufw --force enable
check_error "Failed to enable UFW"
print_success "UFW firewall enabled"

echo ""

###############################################################################
# 6. Join Windows Domain (Active Directory)
###############################################################################

print_info "==================================================================="
print_info "Windows Domain Join Configuration"
print_info "==================================================================="
echo ""

read -p "Do you want to join this server to a Windows domain? (y/n): " join_domain

if [[ "$join_domain" =~ ^[Yy]$ ]]; then

    ###########################################################################
    # 6.1. Install Required Packages
    ###########################################################################

    print_info "Installing required packages for Active Directory integration..."
    apt-get update -qq
    check_error "Failed to update package lists"

    # Pre-configure krb5-config to avoid interactive prompts during installation
    print_info "Pre-configuring Kerberos to avoid interactive prompts..."
    export DEBIAN_FRONTEND=noninteractive

    # Pre-seed the Kerberos configuration with dummy values
    # These will be overwritten by the script later with actual domain settings
    echo "krb5-config krb5-config/default_realm string TEMP.REALM" | debconf-set-selections
    echo "krb5-config krb5-config/kerberos_servers string" | debconf-set-selections
    echo "krb5-config krb5-config/admin_server string" | debconf-set-selections
    echo "krb5-config krb5-config/add_servers boolean false" | debconf-set-selections
    echo "krb5-config krb5-config/read_conf boolean true" | debconf-set-selections

    apt-get install -y realmd sssd sssd-tools adcli krb5-user packagekit samba-common-bin oddjob oddjob-mkhomedir
    check_error "Failed to install AD integration packages"

    # Unset DEBIAN_FRONTEND to restore normal behavior
    unset DEBIAN_FRONTEND

    print_success "Required packages installed successfully (non-interactive)"

    echo ""

    ###########################################################################
    # 6.2. Get Domain Information
    ###########################################################################

    print_info "Enter your Windows domain information:"
    echo ""
    read -p "Domain name (e.g., test.example.local): " DOMAIN_NAME

    # Validate domain name format
    if [[ ! "$DOMAIN_NAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        print_error "Invalid domain name format"
        exit 1
    fi

    echo ""
    print_info "Enter Windows domain admin credentials:"
    print_info "Note: Username can contain special characters like \$ (e.g., admin\$)"
    echo ""

    read -p "Domain admin username: " DOMAIN_ADMIN

    # Validate username is not empty
    if [ -z "$DOMAIN_ADMIN" ]; then
        print_error "Username cannot be empty"
        exit 1
    fi

    # Securely read password
    read -s -p "Domain admin password: " DOMAIN_PASSWORD
    echo ""

    if [ -z "$DOMAIN_PASSWORD" ]; then
        print_error "Password cannot be empty"
        exit 1
    fi

    echo ""

    ###########################################################################
    # 6.3. Discover Domain
    ###########################################################################

    print_info "Discovering domain $DOMAIN_NAME..."
    realm discover "$DOMAIN_NAME" > /tmp/realm_discover.log 2>&1

    if [ $? -eq 0 ]; then
        print_success "Domain $DOMAIN_NAME discovered successfully"
        echo ""
        print_info "Domain information:"
        realm discover "$DOMAIN_NAME" | grep -E "domain-name|configured|server-software"
        echo ""
    else
        print_error "Failed to discover domain $DOMAIN_NAME"
        print_error "Please check:"
        print_error "  - DNS is configured correctly"
        print_error "  - Domain name is correct"
        print_error "  - Network connectivity to domain controllers"
        cat /tmp/realm_discover.log
        exit 1
    fi

    ###########################################################################
    # 6.4. Configure Kerberos
    ###########################################################################

    print_info "Configuring Kerberos..."

    # Convert domain to uppercase for Kerberos realm
    KERBEROS_REALM=$(echo "$DOMAIN_NAME" | tr '[:lower:]' '[:upper:]')

    # Backup existing krb5.conf
    if [ -f /etc/krb5.conf ]; then
        cp /etc/krb5.conf /etc/krb5.conf.backup.$(date +%Y%m%d_%H%M%S)
        print_info "Backed up existing krb5.conf"
    fi

    # Create Kerberos configuration
    cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $KERBEROS_REALM
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    default_ccache_name = KEYRING:persistent:%{uid}

[realms]
    $KERBEROS_REALM = {
        kdc = $DOMAIN_NAME
        admin_server = $DOMAIN_NAME
    }

[domain_realm]
    .$DOMAIN_NAME = $KERBEROS_REALM
    $DOMAIN_NAME = $KERBEROS_REALM
EOF

    check_error "Failed to configure Kerberos"
    print_success "Kerberos configured successfully"

    echo ""

    ###########################################################################
    # 6.5. Test Kerberos Authentication
    ###########################################################################

    print_info "Testing Kerberos authentication..."

    # Test Kerberos ticket acquisition
    echo "$DOMAIN_PASSWORD" | kinit "$DOMAIN_ADMIN@$KERBEROS_REALM" > /tmp/kinit.log 2>&1

    if [ $? -eq 0 ]; then
        print_success "Kerberos authentication successful"

        # Show ticket information
        print_info "Kerberos ticket information:"
        klist | grep -E "Default principal|Valid starting|Expires|renew until"
        echo ""

        # Destroy the ticket for security
        kdestroy
    else
        print_error "Kerberos authentication failed"
        print_error "Please check:"
        print_error "  - Domain admin username is correct"
        print_error "  - Domain admin password is correct"
        print_error "  - Time synchronization with domain controller"
        cat /tmp/kinit.log
        exit 1
    fi

    ###########################################################################
    # 6.6. Join Domain
    ###########################################################################

    print_info "Joining domain $DOMAIN_NAME..."

    # Get the hostname for the computer account
    HOSTNAME=$(hostname -s | tr '[:lower:]' '[:upper:]')
    print_info "Computer name will be: $HOSTNAME"

    # Check if computer already exists in domain and remove if needed
    print_info "Checking if computer account already exists..."
    echo "$DOMAIN_PASSWORD" | kinit "$DOMAIN_ADMIN@$KERBEROS_REALM" > /dev/null 2>&1

    # Try to delete existing computer account if it exists
    adcli delete-computer "$HOSTNAME" --domain="$DOMAIN_NAME" --login-user="$DOMAIN_ADMIN" > /dev/null 2>&1

    # Clean up ticket
    kdestroy > /dev/null 2>&1

    # Now join the domain using adcli with stdin password
    # Using adcli directly gives us better control than realm join
    print_info "Joining domain using adcli..."

    echo "$DOMAIN_PASSWORD" | adcli join "$DOMAIN_NAME" \
        --login-user="$DOMAIN_ADMIN" \
        --stdin-password \
        --domain-ou="CN=Computers" \
        --show-details > /tmp/realm_join.log 2>&1
    JOIN_RESULT=$?

    if [ $JOIN_RESULT -eq 0 ]; then
        print_success "Successfully joined domain $DOMAIN_NAME"

        # Now configure realm to recognize the domain
        print_info "Configuring realm settings..."
        realm list > /dev/null 2>&1

    else
        print_error "Failed to join domain using adcli"
        print_error "Check the error details below:"
        cat /tmp/realm_join.log
        echo ""
        print_error "Common issues:"
        print_error "  - Insufficient permissions (user must be Domain Admin)"
        print_error "  - Computer object already exists in AD (tried to delete)"
        print_error "  - DNS reverse lookup issues"
        print_error "  - Time synchronization problems"
        print_error "  - Special characters in username may need escaping"
        exit 1
    fi

    echo ""

    ###########################################################################
    # 6.7. Configure SSSD
    ###########################################################################

    print_info "Configuring SSSD for domain authentication..."

    # Backup existing sssd.conf
    if [ -f /etc/sssd/sssd.conf ]; then
        cp /etc/sssd/sssd.conf /etc/sssd/sssd.conf.backup.$(date +%Y%m%d_%H%M%S)
        print_info "Backed up existing sssd.conf"
    fi

    # Configure SSSD
    cat > /etc/sssd/sssd.conf << EOF
[sssd]
domains = $DOMAIN_NAME
config_file_version = 2
services = nss, pam

[domain/$DOMAIN_NAME]
ad_domain = $DOMAIN_NAME
krb5_realm = $KERBEROS_REALM
realmd_tags = manages-system joined-with-adcli
cache_credentials = True
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
use_fully_qualified_names = False
fallback_homedir = /home/%u
access_provider = ad
ad_gpo_access_control = permissive
EOF

    check_error "Failed to configure SSSD"

    # Set proper permissions on sssd.conf
    chmod 600 /etc/sssd/sssd.conf
    check_error "Failed to set permissions on sssd.conf"

    print_success "SSSD configured successfully"

    echo ""

    ###########################################################################
    # 6.8. Configure Automatic Home Directory Creation
    ###########################################################################

    print_info "Configuring automatic home directory creation..."

    # Enable pam_mkhomedir
    pam-auth-update --enable mkhomedir > /dev/null 2>&1

    # Ensure mkhomedir is configured in PAM
    if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
        echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0077" >> /etc/pam.d/common-session
        check_error "Failed to configure pam_mkhomedir"
    fi

    print_success "Automatic home directory creation enabled"
    print_info "Domain user home directories will be created at /home/username"

    echo ""

    ###########################################################################
    # 6.9. Configure Firewall for Active Directory
    ###########################################################################

    print_info "Configuring firewall for Active Directory communication..."

    # Allow DNS
    ufw allow 53/tcp comment 'DNS (TCP)'
    ufw allow 53/udp comment 'DNS (UDP)'

    # Allow Kerberos
    ufw allow 88/tcp comment 'Kerberos (TCP)'
    ufw allow 88/udp comment 'Kerberos (UDP)'

    # Allow LDAP
    ufw allow 389/tcp comment 'LDAP (TCP)'
    ufw allow 389/udp comment 'LDAP (UDP)'

    # Allow LDAPS
    ufw allow 636/tcp comment 'LDAPS (TCP)'

    # Allow Kerberos Password Change
    ufw allow 464/tcp comment 'Kerberos Password Change (TCP)'
    ufw allow 464/udp comment 'Kerberos Password Change (UDP)'

    # Allow Global Catalog
    ufw allow 3268/tcp comment 'Global Catalog (TCP)'
    ufw allow 3269/tcp comment 'Global Catalog SSL (TCP)'

    check_error "Failed to configure firewall rules for AD"
    print_success "Firewall configured for Active Directory communication"

    echo ""

    ###########################################################################
    # 6.10. Restart SSSD Service
    ###########################################################################

    print_info "Restarting SSSD service..."
    systemctl restart sssd
    check_error "Failed to restart SSSD"

    # Verify SSSD is running
    if systemctl is-active --quiet sssd; then
        print_success "SSSD service is running"
    else
        print_error "SSSD service is not running"
        systemctl status sssd
        exit 1
    fi

    # Enable SSSD to start on boot
    systemctl enable sssd > /dev/null 2>&1
    print_success "SSSD enabled to start on boot"

    echo ""

    ###########################################################################
    # 6.11. Verify Domain Join
    ###########################################################################

    print_info "Verifying domain join status..."

    realm list | grep -q "$DOMAIN_NAME"
    if [ $? -eq 0 ]; then
        print_success "Server is joined to domain: $DOMAIN_NAME"
        echo ""
        print_info "Domain configuration:"
        realm list
        echo ""
    else
        print_error "Domain join verification failed"
        exit 1
    fi

    ###########################################################################
    # 6.12. Test Domain User Authentication
    ###########################################################################

    print_info "==================================================================="
    print_info "Testing Domain Authentication"
    print_info "==================================================================="
    echo ""

    print_info "Testing if domain users can be queried..."

    # Try to get info about the admin user
    id "$DOMAIN_ADMIN" > /tmp/id_test.log 2>&1

    if [ $? -eq 0 ]; then
        print_success "Successfully queried domain user information"
        print_info "Domain admin user details:"
        id "$DOMAIN_ADMIN"
        echo ""
    else
        print_warning "Could not query domain user yet (this may be normal)"
        print_info "SSSD cache may need time to populate"
        cat /tmp/id_test.log
    fi

    echo ""
    print_info "Testing domain user authentication via PAM..."

    # Check if getent can retrieve domain users
    getent passwd "$DOMAIN_ADMIN" > /tmp/getent_test.log 2>&1

    if [ $? -eq 0 ]; then
        print_success "Domain user lookup successful via NSS"
        print_info "User information from directory:"
        getent passwd "$DOMAIN_ADMIN"
        echo ""
    else
        print_warning "Domain user lookup not yet available"
        print_info "This may take a few moments to propagate"
        cat /tmp/getent_test.log
    fi

    echo ""
    print_success "==================================================================="
    print_success "Domain Join Configuration Complete!"
    print_success "==================================================================="
    echo ""
    print_info "Domain Join Summary:"
    print_success "  - Domain: $DOMAIN_NAME"
    print_success "  - Kerberos realm: $KERBEROS_REALM"
    print_success "  - SSSD: Active and configured"
    print_success "  - Home directories: /home/username (auto-created)"
    print_success "  - Firewall: AD ports opened"
    echo ""
    print_info "Domain users can now login with:"
    print_info "  - Username: domain_username (without domain prefix)"
    print_info "  - Example: ssh -p 555 john.doe@server"
    echo ""
    print_warning "IMPORTANT: Test domain user login before disconnecting!"
    echo ""

    # Clean up sensitive log files
    rm -f /tmp/realm_discover.log /tmp/kinit.log /tmp/realm_join.log /tmp/id_test.log /tmp/getent_test.log 2>/dev/null

else
    print_info "Skipping Windows domain join configuration"
fi

echo ""

###############################################################################
# 7. Display Configuration Summary
###############################################################################

print_info "==================================================================="
print_info "Configuration Summary"
print_info "==================================================================="
echo ""
print_success "Automatic updates: Configured"
print_success "SSH port changed: 22 -> 555"
print_success "Root SSH login: Disabled"
print_success "UFW firewall: Enabled"
print_success "Fail2Ban: Active (5 attempts = permanent ban)"
if [[ "$join_domain" =~ ^[Yy]$ ]]; then
    print_success "Domain join: Completed ($DOMAIN_NAME)"
fi
echo ""
print_info "Active firewall rules:"
ufw status numbered
echo ""

###############################################################################
# 8. Restart SSH Service
###############################################################################

print_warning "==================================================================="
print_warning "IMPORTANT: SSH Service Restart Required"
print_warning "==================================================================="
echo ""
print_warning "The SSH service needs to be restarted for changes to take effect."
print_warning "After restart, you will need to connect using:"
print_warning "  ssh -p 555 user@server"
echo ""
print_warning "If you are connected via SSH, you will be DISCONNECTED!"
print_warning "Make sure you have console access or another way to connect."
echo ""
read -n 1 -s -r -p "Press any key to restart SSH service..."
echo ""
echo ""

print_info "Restarting SSH service..."
systemctl restart ssh
check_error "Failed to restart SSH service"

# Verify SSH is running
if systemctl is-active --quiet ssh; then
    print_success "SSH service restarted successfully"
else
    print_error "SSH service is not running!"
    exit 1
fi

echo ""
print_success "==================================================================="
print_success "Ubuntu Server Hardening Complete!"
print_success "==================================================================="
echo ""
print_info "Next steps:"
print_info "1. Reconnect to SSH using: ssh -p 555 user@server"
print_info "2. Test that root login is blocked"
print_info "3. Verify firewall rules are working as expected"
echo ""
print_warning "Keep this terminal open until you verify you can connect on port 555!"
echo ""

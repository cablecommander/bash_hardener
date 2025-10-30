#!/bin/bash

###############################################################################
# Ubuntu Server Hardening Script
# This script hardens an Ubuntu server by:
# - Configuring automatic updates
# - Changing SSH port (default 555, customizable)
# - Disabling root SSH login
# - Enabling UFW firewall
# - Configuring Fail2Ban for SSH protection
# - Joining Windows Active Directory domain (optional)
# - Allowing custom ports
# - Enhanced input validation with 3-attempt limit
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

# Function to validate yes/no input (Y/n format - Yes is default)
# Returns 0 for yes, 1 for no
validate_yes_no() {
    local prompt="$1"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        read -p "$prompt (Y/n): " response

        # Empty input or yes variants = yes (default)
        if [[ -z "$response" ]] || [[ "$response" =~ ^[Yy]([Ee][Ss])?$ ]]; then
            return 0
        # No variants = no
        elif [[ "$response" =~ ^[Nn]([Oo])?$ ]]; then
            return 1
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Invalid input. Please enter 'y' for yes or 'n' for no."
                print_info "Attempt $attempts of $max_attempts"
            fi
        fi
    done

    print_error "Maximum attempts reached. Exiting for safety."
    exit 1
}

# Function to validate yes/no with explicit "yes" required for critical confirmations
# Returns 0 for yes, 1 for no
validate_yes_explicit() {
    local prompt="$1"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        read -p "$prompt (type 'yes' to confirm): " response

        if [[ "$response" == "yes" ]]; then
            return 0
        elif [[ "$response" =~ ^[Nn]([Oo])?$ ]] || [[ -z "$response" ]]; then
            return 1
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Invalid input. Please type 'yes' to confirm or 'no' to decline."
                print_info "Attempt $attempts of $max_attempts"
            fi
        fi
    done

    print_error "Maximum attempts reached. Exiting for safety."
    exit 1
}

# Function to validate IP address format and range (0-255 per octet)
validate_ip() {
    local ip="$1"

    # Check basic format
    if [[ ! $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi

    # Check each octet is 0-255
    IFS='.' read -ra OCTETS <<< "$ip"
    for octet in "${OCTETS[@]}"; do
        if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            return 1
        fi
    done

    return 0
}

# Function to get validated IP address input
get_validated_ip() {
    local prompt="$1"
    local allow_done="$2"  # Set to "allow_done" to allow typing 'done' or pressing Enter
    local attempts=0
    local max_attempts=3
    local ip_input

    while [ $attempts -lt $max_attempts ]; do
        read -p "$prompt" ip_input

        # Check if 'done' is allowed and entered FIRST (before validation)
        # Empty input (pressing Enter) or typing "done" both exit when allow_done is set
        if [[ "$allow_done" == "allow_done" ]]; then
            if [[ -z "$ip_input" ]] || [[ "$ip_input" == "done" ]]; then
                echo "done"
                return 0
            fi
        fi

        # Check for empty input when allow_done is NOT set
        if [ -z "$ip_input" ]; then
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "IP address cannot be empty."
                print_info "Attempt $attempts of $max_attempts"
            fi
            continue
        fi

        # Validate IP
        if validate_ip "$ip_input"; then
            echo "$ip_input"
            return 0
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Invalid IP address format. Each octet must be 0-255 (e.g., 192.168.1.100)"
                print_info "Attempt $attempts of $max_attempts"
            fi
        fi
    done

    print_error "Maximum attempts reached for IP input. Exiting."
    exit 1
}

# Function to validate port number
validate_port() {
    local port="$1"

    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi

    return 0
}

# Function to get validated port number
get_validated_port() {
    local prompt="$1"
    local allow_done="$2"  # Set to "allow_done" to allow typing 'done' or pressing Enter
    local attempts=0
    local max_attempts=3
    local port_input

    while [ $attempts -lt $max_attempts ]; do
        read -p "$prompt" port_input

        # Check if 'done' is allowed and entered FIRST (before validation)
        # Empty input (pressing Enter) or typing "done" both exit when allow_done is set
        if [[ "$allow_done" == "allow_done" ]]; then
            if [[ -z "$port_input" ]] || [[ "$port_input" == "done" ]]; then
                echo "done"
                return 0
            fi
        fi

        # Check for empty input when allow_done is NOT set
        if [ -z "$port_input" ]; then
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Port number cannot be empty."
                print_info "Attempt $attempts of $max_attempts"
            fi
            continue
        fi

        # Validate port
        if validate_port "$port_input"; then
            echo "$port_input"
            return 0
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Invalid port number. Must be between 1 and 65535"
                print_info "Attempt $attempts of $max_attempts"
            fi
        fi
    done

    print_error "Maximum attempts reached for port input. Exiting."
    exit 1
}

# Function to get validated menu choice
get_validated_choice() {
    local prompt="$1"
    local min="$2"
    local max="$3"
    local attempts=0
    local max_attempts=3
    local choice

    while [ $attempts -lt $max_attempts ]; do
        read -p "$prompt" choice

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge "$min" ] && [ "$choice" -le "$max" ]; then
            echo "$choice"
            return 0
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Invalid choice. Please enter a number between $min and $max"
                print_info "Attempt $attempts of $max_attempts"
            fi
        fi
    done

    print_error "Maximum attempts reached. Exiting."
    exit 1
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
update_choice=$(get_validated_choice "Enter your choice (1-4): " 1 4)

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

# Prompt for SSH port
echo ""
print_info "SSH Port Configuration"
echo ""
print_info "Default SSH port is 22. For security, you should use a different port."

# Get SSH port with validation (allow empty for default)
attempts=0
max_attempts=3
SSH_PORT=""

while [ $attempts -lt $max_attempts ]; do
    read -p "Enter SSH port number (press Enter for default 555): " SSH_PORT

    # If empty, use default 555
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=555
        print_info "Using default port: 555"
        break
    fi

    # Validate port number
    if validate_port "$SSH_PORT"; then
        break
    else
        attempts=$((attempts + 1))
        if [ $attempts -lt $max_attempts ]; then
            print_error "Invalid port number. Must be between 1 and 65535"
            print_info "Attempt $attempts of $max_attempts"
        else
            print_error "Maximum attempts reached. Exiting."
            exit 1
        fi
    fi
done

# Check for commonly used ports and warn
COMMON_PORTS=(80 443 21 25 110 143 3306 5432 6379 27017 8080 8443 3389)
PORT_NAMES=(
    "80:HTTP"
    "443:HTTPS"
    "21:FTP"
    "25:SMTP"
    "110:POP3"
    "143:IMAP"
    "3306:MySQL"
    "5432:PostgreSQL"
    "6379:Redis"
    "27017:MongoDB"
    "8080:HTTP-Alt"
    "8443:HTTPS-Alt"
    "3389:RDP"
)

for port_info in "${PORT_NAMES[@]}"; do
    port_num="${port_info%%:*}"
    port_service="${port_info##*:}"

    if [ "$SSH_PORT" -eq "$port_num" ]; then
        echo ""
        print_warning "==================================================================="
        print_warning "WARNING: Port $SSH_PORT is commonly used for $port_service"
        print_warning "==================================================================="
        print_warning "Using this port for SSH may cause conflicts with $port_service service"
        print_warning "or may be blocked by some firewalls/networks."
        echo ""

        if ! validate_yes_explicit "Are you SURE you want to use port $SSH_PORT for SSH?"; then
            print_info "Please choose a different port."
            SSH_PORT=$(get_validated_port "Enter SSH port number: " "")
        fi
        break
    fi
done

echo ""
print_info "Changing SSH port to $SSH_PORT..."
sed -i "s/^#\?Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
check_error "Failed to change SSH port"

# Verify port change
if grep -q "^Port $SSH_PORT" /etc/ssh/sshd_config; then
    print_success "SSH port changed to $SSH_PORT"
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

# Allow SSH on custom port
print_info "Allowing SSH on port $SSH_PORT..."
ufw allow $SSH_PORT/tcp comment 'SSH'
check_error "Failed to allow port $SSH_PORT"
print_success "Port $SSH_PORT (SSH) allowed through firewall"

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

    if validate_yes_no "Do you want to whitelist $CURRENT_IP?"; then
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

if validate_yes_no "Add more IPs to whitelist?"; then
    while true; do
        echo ""
        whitelist_ip=$(get_validated_ip "Enter IP address to whitelist (or press Enter to finish): " "allow_done")

        if [[ "$whitelist_ip" == "done" ]]; then
            break
        fi

        WHITELIST_IPS+=("$whitelist_ip")
        print_success "Added $whitelist_ip to whitelist"
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

    if ! validate_yes_explicit "Are you SURE you want to continue without a whitelist?"; then
        print_info "Returning to whitelist configuration..."
        whitelist_ip=$(get_validated_ip "Enter at least one IP address to whitelist: " "")
        WHITELIST_IPS+=("$whitelist_ip")
        print_success "Added $whitelist_ip to whitelist"
    fi
fi

echo ""
print_info "Configuring Fail2Ban for SSH on port $SSH_PORT..."

# Build the ignoreip line with whitelisted IPs
IGNORE_IP_LINE="ignoreip = 127.0.0.1/8 ::1"
if [ ${#WHITELIST_IPS[@]} -gt 0 ]; then
    print_info "Adding ${#WHITELIST_IPS[@]} IP(s) to Fail2Ban whitelist..."
    for ip in "${WHITELIST_IPS[@]}"; do
        IGNORE_IP_LINE="$IGNORE_IP_LINE $ip"
    done
fi

# Create custom jail configuration with whitelist included
cat > /etc/fail2ban/jail.d/sshd-custom.conf << EOF
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = -1
findtime = 600
$IGNORE_IP_LINE
action = iptables-multiport[name=SSH, port="$SSH_PORT", protocol=tcp]
EOF

check_error "Failed to create Fail2Ban jail configuration"

# Show whitelisted IPs
if [ ${#WHITELIST_IPS[@]} -gt 0 ]; then
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
    print_info "  - Monitoring: SSH port $SSH_PORT"
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
# 5. Configure Additional Firewall Ports
###############################################################################

print_info "==================================================================="
print_info "Additional Firewall Ports Configuration"
print_info "==================================================================="
echo ""
print_info "You can open additional ports for services running on this server."
print_info "Examples: Web servers (80, 443), databases (3306, 5432), etc."
echo ""

if validate_yes_no "Would you like to open any additional ports?"; then
    while true; do
        echo ""
        port_num=$(get_validated_port "Enter port number (or press Enter to finish): " "allow_done")

        if [[ "$port_num" == "done" ]]; then
            break
        fi

        # Get protocol with validation
        protocol=""
        attempts=0
        max_attempts=3

        while [ $attempts -lt $max_attempts ]; do
            read -p "Protocol (tcp/udp/both): " protocol
            protocol=$(echo "$protocol" | tr '[:upper:]' '[:lower:]')

            if [[ "$protocol" == "tcp" ]] || [[ "$protocol" == "udp" ]] || [[ "$protocol" == "both" ]]; then
                break
            else
                attempts=$((attempts + 1))
                if [ $attempts -lt $max_attempts ]; then
                    print_error "Invalid protocol. Please enter 'tcp', 'udp', or 'both'"
                    print_info "Attempt $attempts of $max_attempts"
                else
                    print_error "Maximum attempts reached. Skipping this port."
                    protocol=""
                    break
                fi
            fi
        done

        # Skip if protocol validation failed
        if [ -z "$protocol" ]; then
            continue
        fi

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

if validate_yes_no "Do you want to join this server to a Windows domain?"; then

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

    # Domain join retry loop
    DOMAIN_JOIN_SUCCESS=0
    while [ $DOMAIN_JOIN_SUCCESS -eq 0 ]; do

        ###########################################################################
        # 6.2. Get Domain Information
        ###########################################################################

    print_info "Enter your Windows domain information:"
    echo ""

    # Get and validate domain name
    attempts=0
    max_attempts=3
    DOMAIN_NAME=""

    while [ $attempts -lt $max_attempts ]; do
        read -p "Domain name (e.g., test.example.local): " DOMAIN_NAME

        # Check if empty
        if [ -z "$DOMAIN_NAME" ]; then
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Domain name cannot be empty"
                print_info "Attempt $attempts of $max_attempts"
            else
                print_error "Maximum attempts reached. Exiting."
                exit 1
            fi
            continue
        fi

        # Validate domain name format - must have at least one dot and valid format
        # Pattern requires: word.word or word.word.word etc.
        if [[ "$DOMAIN_NAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            # Additional check: must not start or end with hyphen, must have at least 2 parts
            if [[ ! "$DOMAIN_NAME" =~ ^- ]] && [[ ! "$DOMAIN_NAME" =~ -$ ]] && [[ "$DOMAIN_NAME" == *.* ]]; then
                break
            else
                attempts=$((attempts + 1))
                if [ $attempts -lt $max_attempts ]; then
                    print_error "Invalid domain name format. Must be FQDN (e.g., example.local or test.example.com)"
                    print_info "Attempt $attempts of $max_attempts"
                else
                    print_error "Maximum attempts reached. Exiting."
                    exit 1
                fi
            fi
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Invalid domain name format. Must be FQDN (e.g., example.local or test.example.com)"
                print_info "Attempt $attempts of $max_attempts"
            else
                print_error "Maximum attempts reached. Exiting."
                exit 1
            fi
        fi
    done

    echo ""
    print_info "Enter Windows domain admin credentials:"
    print_info "Note: Username can contain special characters like \$ (e.g., admin\$)"
    echo ""

    # Get and validate username (required field)
    attempts=0
    DOMAIN_ADMIN=""

    while [ $attempts -lt $max_attempts ]; do
        read -p "Domain admin username: " DOMAIN_ADMIN

        if [ -n "$DOMAIN_ADMIN" ]; then
            break
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Username cannot be empty"
                print_info "Attempt $attempts of $max_attempts"
            else
                print_error "Maximum attempts reached. Exiting."
                exit 1
            fi
        fi
    done

    # Get and validate password (required field)
    attempts=0
    DOMAIN_PASSWORD=""

    while [ $attempts -lt $max_attempts ]; do
        read -s -p "Domain admin password: " DOMAIN_PASSWORD
        echo ""

        if [ -n "$DOMAIN_PASSWORD" ]; then
            break
        else
            attempts=$((attempts + 1))
            if [ $attempts -lt $max_attempts ]; then
                print_error "Password cannot be empty"
                print_info "Attempt $attempts of $max_attempts"
            else
                print_error "Maximum attempts reached. Exiting."
                exit 1
            fi
        fi
    done

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
        echo ""
        cat /tmp/realm_discover.log
        echo ""

        if validate_yes_no "Would you like to try again with different domain information?"; then
            print_info "Restarting domain join process..."
            echo ""
            continue
        else
            print_info "Skipping domain join."
            break
        fi
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

    # Create Kerberos configuration with proper encryption types for AD compatibility
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
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac

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
        echo ""
        cat /tmp/kinit.log
        echo ""

        if validate_yes_no "Would you like to try again with different credentials?"; then
            print_info "Restarting domain join process..."
            echo ""
            continue
        else
            print_info "Skipping domain join."
            break
        fi
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

    # Install additional packages that may help with authentication
    print_info "Installing additional authentication packages..."
    apt-get install -y libsasl2-modules-gssapi-mit samba-common-tools > /dev/null 2>&1

    # Now join the domain using realm join with a password file
    print_info "Joining domain using realm..."

    # Create a temporary password file (more reliable than stdin for special characters)
    PASS_FILE=$(mktemp)
    chmod 600 "$PASS_FILE"
    echo -n "$DOMAIN_PASSWORD" > "$PASS_FILE"

    # Try realm join with password file
    realm join --membership-software=samba --client-software=sssd \
        --user="$DOMAIN_ADMIN" "$DOMAIN_NAME" < "$PASS_FILE" > /tmp/realm_join.log 2>&1
    JOIN_RESULT=$?

    # Clean up password file immediately
    rm -f "$PASS_FILE"

    if [ $JOIN_RESULT -eq 0 ]; then
        print_success "Successfully joined domain $DOMAIN_NAME"
        echo ""

        # Verify the join worked
        print_info "Verifying domain join..."
        sleep 2

        if realm list | grep -q "$DOMAIN_NAME"; then
            print_success "Domain join verified with realm"
            realm list
        else
            print_warning "Realm list doesn't show domain, but join may have succeeded"
        fi

    else
        print_error "Failed to join domain"
        print_error "Check the error details below:"
        cat /tmp/realm_join.log
        echo ""
        print_error "Common issues:"
        print_error "  - Insufficient permissions (user must be Domain Admin)"
        print_error "  - Computer object already exists in AD"
        print_error "  - DNS reverse lookup issues"
        print_error "  - Time synchronization problems"
        echo ""
        print_error "Troubleshooting commands to run manually:"
        print_error "  realm discover $DOMAIN_NAME"
        print_error "  getent passwd $DOMAIN_ADMIN"
        print_error "  sudo realm join --verbose $DOMAIN_NAME"
        echo ""

        if validate_yes_no "Would you like to try again with different information?"; then
            print_info "Restarting domain join process..."
            echo ""
            continue
        else
            print_info "Skipping domain join."
            break
        fi
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

    print_info "==================================================================="
    print_info "Comprehensive Domain Join Verification"
    print_info "==================================================================="
    echo ""

    VERIFICATION_FAILED=0

    # Test 1: Realm list
    print_info "Test 1: Checking realm list..."
    if realm list | grep -q "$DOMAIN_NAME"; then
        print_success "✓ Realm shows domain: $DOMAIN_NAME"
        realm list | grep -E "domain-name|configured|login-policy"
    else
        print_error "✗ Domain not found in realm list"
        VERIFICATION_FAILED=1
    fi
    echo ""

    # Test 2: Check if computer account exists
    print_info "Test 2: Checking computer account..."
    if adcli show-computer > /dev/null 2>&1; then
        print_success "✓ Computer account exists in AD"
        adcli show-computer 2>/dev/null | head -5
    else
        print_warning "✗ Could not verify computer account"
        VERIFICATION_FAILED=1
    fi
    echo ""

    # Test 3: Check SSSD domain status
    print_info "Test 3: Checking SSSD domain status..."
    if sssctl domain-status "$DOMAIN_NAME" > /dev/null 2>&1; then
        print_success "✓ SSSD can communicate with domain"
        sssctl domain-status "$DOMAIN_NAME" | head -10
    else
        print_warning "✗ SSSD domain status check failed"
        VERIFICATION_FAILED=1
    fi
    echo ""

    # Test 4: Check NSS configuration
    print_info "Test 4: Checking NSS configuration..."
    if grep -q "sss" /etc/nsswitch.conf; then
        print_success "✓ NSS is configured for SSSD"
    else
        print_error "✗ NSS not configured for SSSD"
        VERIFICATION_FAILED=1
    fi
    echo ""

    # Test 5: Check PAM configuration
    print_info "Test 5: Checking PAM configuration..."
    if grep -q "pam_sss.so" /etc/pam.d/common-auth; then
        print_success "✓ PAM is configured for SSSD authentication"
    else
        print_error "✗ PAM not configured for SSSD"
        VERIFICATION_FAILED=1
    fi
    echo ""

    if [ $VERIFICATION_FAILED -eq 1 ]; then
        print_warning "Some verification tests failed"
        print_warning "The domain join may be incomplete or not working correctly"
        echo ""
        print_info "To troubleshoot, run these commands:"
        print_info "  sudo realm list"
        print_info "  sudo systemctl status sssd"
        print_info "  sudo journalctl -xe -u sssd"
        print_info "  sudo sssctl domain-status $DOMAIN_NAME"
        echo ""
    else
        print_success "All domain join verification tests passed!"
        echo ""
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
    print_info "  - Example: ssh -p $SSH_PORT john.doe@server"
    echo ""
    print_warning "IMPORTANT: Test domain user login before disconnecting!"
    echo ""

    # Clean up sensitive log files
    rm -f /tmp/realm_discover.log /tmp/kinit.log /tmp/realm_join.log /tmp/id_test.log /tmp/getent_test.log 2>/dev/null

    # Set success flag to exit the retry loop
    DOMAIN_JOIN_SUCCESS=1

    done  # End of domain join retry loop

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
print_success "SSH port changed: 22 -> $SSH_PORT"
print_success "Root SSH login: Disabled"
print_success "UFW firewall: Enabled"
print_success "Fail2Ban: Active (5 attempts = permanent ban)"
if [ -n "$DOMAIN_NAME" ]; then
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
print_warning "  ssh -p $SSH_PORT user@server"
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
print_info "1. Reconnect to SSH using: ssh -p $SSH_PORT user@server"
print_info "2. Test that root login is blocked"
print_info "3. Verify firewall rules are working as expected"
echo ""
print_warning "Keep this terminal open until you verify you can connect on port $SSH_PORT!"
echo ""

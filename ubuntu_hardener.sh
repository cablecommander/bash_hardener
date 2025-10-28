#!/bin/bash

###############################################################################
# Ubuntu Server Hardening Script
# This script hardens an Ubuntu server by:
# - Configuring automatic updates
# - Changing SSH port to 555
# - Disabling root SSH login
# - Enabling UFW firewall
# - Configuring Fail2Ban for SSH protection
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
# 6. Display Configuration Summary
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
echo ""
print_info "Active firewall rules:"
ufw status numbered
echo ""

###############################################################################
# 7. Restart SSH Service
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

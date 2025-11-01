# Ubuntu Server Hardening Script

A comprehensive, interactive bash script designed to automate the hardening of Ubuntu servers with security best practices. This script provides an easy-to-use interface for system administrators to enhance server security through automated configuration of updates, SSH, firewall rules, fail2ban protection, and optional Active Directory integration.

## Table of Contents

- [Features](#features)
- [System Requirements](#system-requirements)
- [Security Disclaimer](#security-disclaimer)
- [Installation](#installation)
- [Usage](#usage)
- [What the Script Does](#what-the-script-does)
- [Configuration Options](#configuration-options)
- [Example Output](#example-output)
- [Files Modified](#files-modified)
- [Post-Installation Verification](#post-installation-verification)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Automatic Updates Configuration**: Choose from security-only, all updates, auto-download, or disable
- **SSH Hardening**: Custom port configuration with validation and root login disabled
- **UFW Firewall**: Automated firewall setup with default deny policies
- **Fail2Ban Protection**: SSH brute-force protection with permanent bans and IP whitelisting
- **Active Directory Integration**: Optional Windows domain join with SSSD configuration
- **Custom Port Management**: Open additional ports for services with protocol selection
- **Input Validation**: Enhanced validation with 3-attempt limits to prevent configuration errors
- **Smart Defaults**: Sensible default values (SSH port 555) with easy customization
- **Color-Coded Output**: Clear success, error, and warning messages for easy monitoring

## System Requirements

- **Operating System**: Ubuntu Server 22.04 LTS or newer
- **Privileges**: Root/sudo access required
- **Architecture**: x86_64 (amd64)
- **Network**: Active internet connection for package installation
- **Access**: Console or IPMI access recommended (script will restart SSH service)

**Tested On:**
- Ubuntu Server 22.04 LTS
- Ubuntu Server 24.04 LTS

> **Note**: While the script may work on older versions, it has been specifically tested and validated on Ubuntu 22.04 and newer releases.

## Security Disclaimer

**IMPORTANT - READ BEFORE RUNNING:**

This script makes significant changes to your server's security configuration, including:
- Modifying SSH settings and changing the default port
- Configuring firewall rules that may block traffic
- Enabling permanent IP bans after failed login attempts
- Potentially joining the server to an Active Directory domain

**Before running in production:**

1. **Test in a non-production environment first** - Always test the script on a development or staging server
2. **Ensure console access** - Have physical or IPMI/KVM access available in case SSH connectivity is lost
3. **Review all settings** - Understand each configuration option before applying
4. **Document your choices** - Keep a record of custom ports and settings configured
5. **Backup critical files** - The script creates backups, but maintain your own as well
6. **Verify connectivity** - After running, verify you can connect before closing your current session
7. **Whitelist your IP** - Always whitelist your management IP in Fail2Ban to prevent lockouts

**Use at your own risk.** This script is provided as-is without warranty. The authors are not responsible for any system lockouts, connectivity issues, or data loss.

## Installation

### Step 1: Clone the Repository

```bash
# Clone the repository from GitHub
git clone https://github.com/yourusername/bash_hardener.git

# Navigate to the project directory
cd bash_hardener
```

### Step 2: Make the Script Executable

```bash
# Set executable permissions on the script
chmod +x ubuntu_hardener.sh
```

### Step 3: Verify the Script

```bash
# Check that the file has execute permissions
ls -l ubuntu_hardener.sh

# Expected output:
# -rwxr-xr-x 1 user user 49487 Oct 30 20:24 ubuntu_hardener.sh
```

## Usage

### Basic Execution

Run the script with sudo privileges:

```bash
sudo ./ubuntu_hardener.sh
```

The script will guide you through an interactive configuration process with prompts for each hardening option.

### What to Expect

1. **Interactive Prompts**: Answer questions about your preferred configuration
2. **Input Validation**: Invalid inputs will prompt for re-entry (3 attempts maximum)
3. **Real-time Feedback**: Color-coded messages show progress and status
4. **Automatic Configuration**: Script applies settings based on your choices
5. **Summary Report**: Final summary of all changes made


## What the Script Does

### 1. Automatic Updates Configuration

Configures Ubuntu's unattended-upgrades package with four options:

- **Option 1**: Security updates only (recommended for stability)
- **Option 2**: All updates automatically installed
- **Option 3**: Auto-download only, manual installation required
- **Option 4**: Disable automatic updates entirely

**Files Modified:**
- `/etc/apt/apt.conf.d/50unattended-upgrades`
- `/etc/apt/apt.conf.d/20auto-upgrades`

### 2. SSH Hardening

Changes the SSH port from default (22) and disables root login:

- **Default Port**: 555 (customizable to any valid port 1-65535)
- **Port Validation**: Warns about commonly used ports (HTTP, HTTPS, MySQL, etc.)
- **Root Login**: Automatically disabled for security
- **Configuration Test**: Validates SSH config before applying changes

**Files Modified:**
- `/etc/ssh/sshd_config`

### 3. UFW Firewall Configuration

Sets up Ubuntu's Uncomplicated Firewall with secure defaults:

- **Default Policy**: Deny all incoming, allow all outgoing
- **SSH Port**: Automatically opens your custom SSH port
- **Additional Ports**: Interactive prompt to open service ports
- **Protocol Selection**: Choose TCP, UDP, or both for each port
- **Port Comments**: Add descriptions for documentation

### 4. Fail2Ban Protection

Configures Fail2Ban to protect against SSH brute-force attacks:

- **Auto-Detection**: Attempts to detect your current IP address
- **IP Whitelisting**: Option to whitelist trusted IPs (highly recommended)
- **Ban Settings**:
  - Max retries: 5 failed attempts
  - Time window: 10 minutes (600 seconds)
  - Ban duration: **PERMANENT** (-1)
- **Monitoring**: Active monitoring on your custom SSH port

**Files Created:**
- `/etc/fail2ban/jail.d/sshd-custom.conf`

**Critical Warning**: If no IPs are whitelisted, failed login attempts will result in permanent lockout requiring console access to recover.

### 5. Active Directory Integration (Optional)

Join the Ubuntu server to a Windows Active Directory domain:

- **Package Installation**: Realmd, SSSD, Kerberos, and Samba tools
- **Domain Discovery**: Automatic domain controller discovery via DNS
- **Kerberos Configuration**: Automatic `/etc/krb5.conf` generation
- **SSSD Setup**: Configured for AD authentication with credential caching
- **Home Directories**: Automatic creation at `/home/username`
- **Firewall Rules**: Opens required AD ports (DNS, Kerberos, LDAP, etc.)
- **Verification**: Multi-step verification of successful domain join

**Files Modified:**
- `/etc/krb5.conf`
- `/etc/sssd/sssd.conf`
- `/etc/pam.d/common-session`
- `/etc/nsswitch.conf` (via realmd)

**Firewall Ports Opened for AD:**
- DNS: 53/tcp, 53/udp
- Kerberos: 88/tcp, 88/udp
- LDAP: 389/tcp, 389/udp
- LDAPS: 636/tcp
- Kerberos Password: 464/tcp, 464/udp
- Global Catalog: 3268/tcp, 3269/tcp

### 6. Additional Firewall Ports

Open custom ports for your services:

- **Interactive Addition**: Add ports one at a time
- **Protocol Options**: TCP, UDP, or both
- **Service Descriptions**: Label each port for documentation
- **Live Preview**: See current rules after each addition

### 7. Configuration Summary & SSH Restart

Final steps:

- **Summary Display**: Shows all configured settings
- **Firewall Rules**: Lists all active UFW rules
- **SSH Restart Warning**: Clear warning about connection disruption
- **Verification Prompts**: Reminds you to test before disconnecting

## Configuration Options

### Automatic Updates Menu

```
Please select your automatic update preference:
1) Only security updates auto-install
2) All updates auto-install
3) Auto-download but manual install
4) Disable auto-updates

Enter your choice (1-4):
```

### SSH Port Configuration

```
Enter SSH port number (press Enter for default 555):
```

- Port range: 1-65535
- Default: 555
- Validation: Warns if port conflicts with common services

### Fail2Ban Whitelist

```
Your current IP address appears to be: 192.168.1.100

Do you want to whitelist 192.168.1.100? (Y/n):

Add more IPs to whitelist? (Y/n):
Enter IP address to whitelist (or press Enter to finish):
```

### Additional Ports

```
Enter port number (or press Enter to finish):
Protocol (tcp/udp/both):
Description/Service name:
```

### Active Directory Join

```
Do you want to join this server to a Windows domain? (Y/n):
Domain name (e.g., test.example.local):
Domain admin username:
Domain admin password:
```

## Example Output

### Initial Startup

```
===================================================================
Ubuntu Server Hardening Script
===================================================================

Configuring automatic updates...

Please select your automatic update preference:
1) Only security updates auto-install
2) All updates auto-install
3) Auto-download but manual install
4) Disable auto-updates

Enter your choice (1-4): 1
[INFO] Configuring security updates only...
[SUCCESS] Security updates configured successfully
```

### SSH Configuration

```
Configuring SSH settings...

SSH Port Configuration

[INFO] Default SSH port is 22. For security, you should use a different port.
Enter SSH port number (press Enter for default 555): 2222
[INFO] Changing SSH port to 2222...
[SUCCESS] SSH port changed to 2222
[INFO] Disabling root SSH login...
[SUCCESS] Root SSH login disabled
[INFO] Testing SSH configuration...
[SUCCESS] SSH configuration is valid
```

### Fail2Ban Setup

```
===================================================================
Configuring Fail2Ban for SSH Protection
===================================================================

[INFO] Installing Fail2Ban...
[SUCCESS] Fail2Ban installed successfully

[INFO] Detecting your current IP address...
[INFO] Your current IP address appears to be: 203.0.113.50

[WARNING] STRONGLY RECOMMENDED: Whitelist your current IP to prevent lockout!
Do you want to whitelist 203.0.113.50? (Y/n): y
[SUCCESS] Added 203.0.113.50 to whitelist

[INFO] Would you like to add additional IPs to the whitelist?
[INFO] (Whitelisted IPs will NEVER be banned by Fail2Ban)
Add more IPs to whitelist? (Y/n): y

Enter IP address to whitelist (or press Enter to finish): 203.0.113.51
[SUCCESS] Added 203.0.113.51 to whitelist

Enter IP address to whitelist (or press Enter to finish):
[INFO] Configuring Fail2Ban for SSH on port 2222...
[INFO] Adding 2 IP(s) to Fail2Ban whitelist...
[SUCCESS] Whitelisted IPs:
[SUCCESS]   - 203.0.113.50
[SUCCESS]   - 203.0.113.51
[INFO] Restarting Fail2Ban service...
[SUCCESS] Fail2Ban is running and monitoring SSH on port 555
[SUCCESS] SSH jail is active and monitoring

[INFO] Fail2Ban Configuration:
[INFO]   - Monitoring: SSH port 2222
[INFO]   - Max retries: 5 failed attempts
[INFO]   - Ban duration: PERMANENT
[INFO]   - Time window: 10 minutes
[INFO]   - Whitelisted IPs: 2
```

### Firewall Configuration

```
===================================================================
Additional Firewall Ports Configuration
===================================================================

[INFO] You can open additional ports for services running on this server.
[INFO] Examples: Web servers (80, 443), databases (3306, 5432), etc.

Would you like to open any additional ports? (Y/n): y

Enter port number (or press Enter to finish): 80
Protocol (tcp/udp/both): tcp
Description/Service name: HTTP Web Server
[SUCCESS] Port 80/tcp allowed for HTTP Web Server

[INFO] Current firewall rules:
Added user rules:
ufw allow 2222/tcp # SSH
ufw allow 80/tcp # HTTP Web Server

Enter port number (or press Enter to finish): 443
Protocol (tcp/udp/both): tcp
Description/Service name: HTTPS Web Server
[SUCCESS] Port 443/tcp allowed for HTTPS Web Server

Enter port number (or press Enter to finish):

[INFO] Enabling UFW firewall...
[SUCCESS] UFW firewall enabled
```

### Final Summary

```
===================================================================
Configuration Summary
===================================================================

[SUCCESS] Automatic updates: Configured
[SUCCESS] SSH port changed: 22 -> 2222
[SUCCESS] Root SSH login: Disabled
[SUCCESS] UFW firewall: Enabled
[SUCCESS] Fail2Ban: Active (5 attempts = permanent ban)

[INFO] Active firewall rules:
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 2222/tcp                   ALLOW IN    Anywhere                   # SSH
[ 2] 80/tcp                     ALLOW IN    Anywhere                   # HTTP Web Server
[ 3] 443/tcp                    ALLOW IN    Anywhere                   # HTTPS Web Server
[ 4] 2222/tcp (v6)              ALLOW IN    Anywhere (v6)              # SSH
[ 5] 80/tcp (v6)                ALLOW IN    Anywhere (v6)              # HTTP Web Server
[ 6] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # HTTPS Web Server

===================================================================
IMPORTANT: SSH Service Restart Required
===================================================================

[WARNING] The SSH service needs to be restarted for changes to take effect.
[WARNING] After restart, you will need to connect using:
[WARNING]   ssh -p 2222 user@server

[WARNING] If you are connected via SSH, you will be DISCONNECTED!
[WARNING] Make sure you have console access or another way to connect.

Press any key to restart SSH service...

[INFO] Restarting SSH service...
[SUCCESS] SSH service restarted successfully

===================================================================
Ubuntu Server Hardening Complete!
===================================================================

[INFO] Next steps:
[INFO] 1. Reconnect to SSH using: ssh -p 2222 user@server
[INFO] 2. Test that root login is blocked
[INFO] 3. Verify firewall rules are working as expected

[WARNING] Keep this terminal open until you verify you can connect on port 2222!
```

## Files Modified

The script modifies the following system files (backups are created where applicable):

### Configuration Files Created/Modified

| File | Purpose | Backup Created |
|------|---------|----------------|
| `/etc/apt/apt.conf.d/50unattended-upgrades` | Automatic update configuration | No |
| `/etc/apt/apt.conf.d/20auto-upgrades` | Update scheduling | No |
| `/etc/ssh/sshd_config` | SSH server configuration | No (manually recommended) |
| `/etc/fail2ban/jail.d/sshd-custom.conf` | Fail2Ban SSH jail | N/A (new file) |
| `/etc/krb5.conf` | Kerberos configuration | Yes (timestamped) |
| `/etc/sssd/sssd.conf` | SSSD authentication | Yes (timestamped) |
| `/etc/pam.d/common-session` | PAM home directory creation | No |

### Services Affected

- `ssh` / `sshd` - Restarted after configuration
- `ufw` - Enabled with new rules
- `fail2ban` - Installed, configured, and started
- `sssd` - Configured and started (if AD join performed)

## Post-Installation Verification

After running the script, verify the hardening was successful:

### 1. Test SSH Connection

```bash
# From another terminal/machine, test new SSH port
ssh -p 2222 username@server_ip

# Verify root login is blocked (should fail)
ssh -p 2222 root@server_ip
```

### 2. Check Firewall Status

```bash
# View active firewall rules
sudo ufw status verbose

# Check specific port
sudo ufw status | grep 2222
```

### 3. Verify Fail2Ban

```bash
# Check Fail2Ban status
sudo systemctl status fail2ban

# View SSH jail status
sudo fail2ban-client status sshd

# Check whitelisted IPs
sudo fail2ban-client get sshd ignoreip
```

### 4. Test Automatic Updates

```bash
# Check unattended-upgrades configuration
cat /etc/apt/apt.conf.d/20auto-upgrades

# Run a dry-run test
sudo unattended-upgrades --dry-run --debug
```

### 5. Verify Domain Join (if applicable)

```bash
# Check realm status
sudo realm list

# Test domain user lookup
id domain_username

# Check SSSD status
sudo systemctl status sssd

# View domain status
sudo sssctl domain-status your.domain.com
```

## Advanced Usage

### Running Non-Interactively

The script is designed for interactive use. For automated deployments, consider:
- Pre-configuring settings in the script
- Creating wrapper scripts with expect
- Using configuration management tools (Ansible, Puppet, etc.)

### Customizing Default Values

Edit the script to change default values:

```bash
# Line 405-409: Change default SSH port
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=555  # Change this value
    print_info "Using default port: 555"
    break
fi
```


## License

This project is provided as-is for educational and administrative purposes. Please review and test thoroughly before use in production environments.

---

**Last Updated**: November 2025
**Repository**: https://github.com/cablecommander/bash_hardener

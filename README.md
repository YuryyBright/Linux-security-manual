# Linux Security Hardening Toolkit

A comprehensive security hardening solution for Linux systems operating in hostile cyber environments. This toolkit provides automated scripts and configurations for maximum security, privacy, and anonymity.

## 🛡️ Overview

This toolkit is designed for security-conscious users who need to protect their Linux systems against advanced persistent threats, surveillance, and cyber attacks. It implements defense-in-depth strategies with multiple layers of security.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/YuryyBright/linux-security-toolkit.git
cd linux-security-toolkit

# Make scripts executable
chmod +x scripts/*.sh

# Run the main setup
sudo ./setup.sh
```

## 📋 Prerequisites

- Ubuntu 22.04 LTS or Debian 11+ (recommended)
- Root or sudo access
- Minimum 20GB free disk space
- Internet connection for initial setup

## 🔧 Features

### Core Security
- **Full Disk Encryption**: LUKS2 with Argon2id
- **Secure Boot**: UEFI with Secure Boot support
- **Firewall**: iptables with strict rules
- **AppArmor**: Mandatory Access Control
- **Network Security**: DNS over TLS/HTTPS, VPN, Tor

### Privacy & Anonymity
- **MAC Address Randomization**
- **Tor Integration**: System-wide anonymization
- **VPN Support**: WireGuard configuration
- **Browser Hardening**: Firefox security profiles

### Monitoring & Detection
- **IDS/IPS**: Suricata with real-time alerts
- **HIDS**: OSSEC for host intrusion detection
- **Fail2ban**: Automatic IP blocking
- **Security Auditing**: Automated security checks

### Encryption
- **Multi-layer Encryption**: System, home, and file-level
- **GPG Integration**: Secure file encryption
- **eCryptfs**: Encrypted home directories
- **VeraCrypt**: Hidden encrypted containers

## 📁 Project Structure

```
linux-security-manual/
├── README.md
├── setup.sh                 # Main installation script
├── config/
│   ├── variables.conf       # Configuration variables
│   ├── firewall.rules       # iptables rules
│   ├── sysctl.conf         # Kernel hardening
│   └── ssh_config          # SSH hardening
├── scripts/
│   ├── 01_disk_encryption.sh
│   ├── 02_system_hardening.sh
│   ├── 03_network_security.sh
│   ├── 04_anonymity.sh
│   ├── 05_monitoring.sh
│   └── 06_maintenance.sh
├── configs/
│   ├── apparmor/
│   ├── fail2ban/
│   ├── ossec/
│   └── suricata/
└── docs/
    ├── INSTALL.md
    ├── USAGE.md
    └── TROUBLESHOOTING.md
```

## ⚙️ Configuration

Edit `config/variables.conf` before running the setup:

```bash
# Essential variables
BACKUP_DIR="/mnt/backup"
SSH_PORT="2222"
VPN_SERVER="your-vpn-server.com"
GPG_EMAIL="your.email@domain.com"
```

## 🔐 Security Levels

The toolkit supports three security levels:

1. **Standard**: Basic hardening (home/office use)
2. **Enhanced**: Advanced protection (sensitive environments)
3. **Maximum**: Full anonymity and security (hostile environments)

```bash
# Set security level during installation
sudo ./setup.sh --level=maximum
```

## 📊 Components

### 1. Disk Encryption
- LUKS2 with 512-bit AES-XTS
- Argon2id key derivation
- Secure key management

### 2. System Hardening
- Kernel parameter tuning
- Secure boot configuration
- Service minimization
- User privilege restrictions

### 3. Network Security
- Firewall with strict default-deny policy
- DNS over HTTPS (DoH)
- VPN auto-connection
- Network intrusion detection

### 4. Anonymity Tools
- Tor integration
- MAC address randomization
- Browser fingerprint protection
- Proxy chains configuration

### 5. Monitoring
- Real-time threat detection
- Log analysis and alerting
- System integrity checking
- Automated incident response

## 📚 Usage

### Basic Commands

```bash
# Check security status
sudo security-status

# Run security audit
sudo security-audit

# Update security rules
sudo security-update

# View security logs
sudo security-logs
```

### Emergency Commands

```bash
# Lockdown mode (blocks all network)
sudo emergency-lockdown

# Secure wipe
sudo secure-wipe /path/to/file

# Panic mode (encrypts and locks system)
sudo panic-mode
```

## 🔄 Updates

Keep your security toolkit updated:

```bash
# Update toolkit
git pull origin main
sudo ./scripts/update.sh

# Update system security
sudo apt update && sudo apt upgrade
sudo security-update
```

## ⚠️ Important Notes

1. **Backup**: Always backup important data before installation
2. **Testing**: Test in a VM before production deployment
3. **Performance**: Maximum security may impact system performance
4. **Recovery**: Keep recovery keys in a secure location
5. **Updates**: Regular updates are crucial for security

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the GPL-3.0 License - see [LICENSE](LICENSE) for details.

## 🔗 Resources

- [Security Documentation](docs/)
- [Issue Tracker](https://github.com/YuryyBright/linux-security-toolkit/issues)
- [Security Updates](https://github.com/YuryyBright/linux-security-toolkit/security)

## ⚡ Quick Security Check

Run this command to verify your security status:

```bash
curl -sSL https://raw.githubusercontent.com/YuryyBright/linux-security-toolkit/main/scripts/quick-check.sh | bash
```

---

**Remember**: Security is a process, not a product. Stay vigilant and keep your system updated.

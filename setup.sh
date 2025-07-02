#!/bin/bash
# Linux Security Toolkit - Main Setup Script
# Run with: sudo ./setup.sh [--level=standard|enhanced|maximum]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/variables.conf"

# Functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log "Configuration loaded from $CONFIG_FILE"
    else
        error "Configuration file not found: $CONFIG_FILE"
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --level=*)
                SECURITY_LEVEL="${1#*=}"
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
        shift
    done
}

# Show help
show_help() {
    cat << EOF
Linux Security Toolkit Setup

Usage: sudo ./setup.sh [OPTIONS]

Options:
    --level=LEVEL    Set security level (standard|enhanced|maximum)
    --help, -h       Show this help message

Security Levels:
    standard  - Basic hardening for home/office use
    enhanced  - Advanced protection for sensitive environments  
    maximum   - Full security for hostile environments

Example:
    sudo ./setup.sh --level=maximum

EOF
}

# Check system compatibility
check_system() {
    log "Checking system compatibility..."
    
    # Check distribution
    if [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
        VERSION=$(cat /etc/debian_version)
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="redhat"
        VERSION=$(cat /etc/redhat-release)
    else
        error "Unsupported distribution"
    fi
    
    # Check architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" ]]; then
        warning "This toolkit is optimized for x86_64 architecture"
    fi
    
    # Check disk space
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 20971520 ]]; then  # 20GB in KB
        error "Insufficient disk space. At least 20GB required"
    fi
    
    log "System check passed: $DISTRO $VERSION ($ARCH)"
}

# Create backup
create_backup() {
    log "Creating system backup..."
    
    BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="/tmp/security_backup_$BACKUP_DATE"
    
    mkdir -p "$BACKUP_PATH"
    
    # Backup important files
    cp -r /etc/ssh "$BACKUP_PATH/" 2>/dev/null || true
    cp -r /etc/iptables "$BACKUP_PATH/" 2>/dev/null || true
    cp /etc/fstab "$BACKUP_PATH/" 2>/dev/null || true
    cp /etc/sysctl.conf "$BACKUP_PATH/" 2>/dev/null || true
    
    tar -czf "$BACKUP_PATH.tar.gz" -C /tmp "security_backup_$BACKUP_DATE"
    rm -rf "$BACKUP_PATH"
    
    log "Backup created: $BACKUP_PATH.tar.gz"
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    apt-get update
    
    # Core packages
    PACKAGES=(
        "cryptsetup"
        "lvm2"
        "iptables"
        "iptables-persistent"
        "fail2ban"
        "aide"
        "rkhunter"
        "clamav"
        "clamav-daemon"
        "apparmor"
        "apparmor-utils"
        "auditd"
        "rsyslog"
        "logrotate"
    )
    
    # Network security packages
    PACKAGES+=(
        "tor"
        "torsocks"
        "proxychains4"
        "wireguard"
        "wireguard-tools"
        "openvpn"
        "stunnel4"
        "dnscrypt-proxy"
    )
    
    # Monitoring packages
    PACKAGES+=(
        "suricata"
        "ossec-hids"
        "tripwire"
        "logwatch"
        "sysstat"
        "htop"
        "iotop"
        "nethogs"
    )
    
    # Additional tools
    PACKAGES+=(
        "git"
        "curl"
        "wget"
        "gpg"
        "openssl"
        "secure-delete"
        "bleachbit"
        "macchanger"
        "firefox"
    )
    
    apt-get install -y "${PACKAGES[@]}"
    
    log "Dependencies installed successfully"
}

# Run security scripts
run_security_scripts() {
    log "Running security configuration scripts..."
    
    local scripts=(
        "01_disk_encryption.sh"
        "02_system_hardening.sh"
        "03_network_security.sh"
        "04_anonymity.sh"
        "05_monitoring.sh"
        "06_maintenance.sh"
    )
    
    for script in "${scripts[@]}"; do
        script_path="${SCRIPT_DIR}/scripts/${script}"
        if [[ -f "$script_path" ]]; then
            log "Running $script..."
            bash "$script_path"
        else
            warning "Script not found: $script_path"
        fi
    done
}

# Configure services
configure_services() {
    log "Configuring system services..."
    
    # Disable unnecessary services
    local disable_services=(
        "bluetooth"
        "cups"
        "avahi-daemon"
        "ModemManager"
    )
    
    for service in "${disable_services[@]}"; do
        systemctl disable "$service" 2>/dev/null || true
        systemctl stop "$service" 2>/dev/null || true
    done
    
    # Enable security services
    local enable_services=(
        "fail2ban"
        "apparmor"
        "auditd"
        "clamav-daemon"
    )
    
    for service in "${enable_services[@]}"; do
        systemctl enable "$service"
        systemctl start "$service"
    done
    
    log "Services configured"
}

# Final security check
final_check() {
    log "Running final security check..."
    
    # Check firewall
    if iptables -L -n | grep -q "DROP"; then
        info "✓ Firewall is active"
    else
        warning "✗ Firewall may not be properly configured"
    fi
    
    # Check SSH
    if [[ -f /etc/ssh/sshd_config ]]; then
        if grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
            info "✓ SSH root login disabled"
        else
            warning "✗ SSH root login may be enabled"
        fi
    fi
    
    # Check updates
    if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
        info "✓ Automatic updates configured"
    else
        warning "✗ Automatic updates not configured"
    fi
    
    # Check encryption
    if lsblk -o NAME,FSTYPE | grep -q "crypto_LUKS"; then
        info "✓ Disk encryption detected"
    else
        warning "✗ Disk encryption not detected"
    fi
}

# Main execution
main() {
    clear
    echo "╔════════════════════════════════════════╗"
    echo "║    Linux Security Toolkit Setup        ║"
    echo "╚════════════════════════════════════════╝"
    echo
    
    check_root
    parse_args "$@"
    load_config
    
    log "Starting security setup (Level: $SECURITY_LEVEL)"
    
    # Confirmation
    read -p "This will modify system configurations. Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Setup cancelled"
        exit 0
    fi
    
    # Run setup steps
    check_system
    create_backup
    install_dependencies
    run_security_scripts
    configure_services
    final_check
    
    log "Security setup completed!"
    info "Please reboot your system to apply all changes"
    info "Review the security audit: sudo security-audit"
    
    # Create completion marker
    touch /etc/security-toolkit.installed
}

# Run main function
main "$@"

#!/bin/bash
# Disk Encryption Setup Script

set -euo pipefail
source "$(dirname "$0")/../config/variables.conf"

log() { echo "[ENCRYPT] $1"; }
error() { echo "[ERROR] $1" >&2; exit 1; }

# Check if already encrypted
check_encryption_status() {
    if lsblk -o NAME,FSTYPE | grep -q "crypto_LUKS"; then
        log "System already encrypted"
        return 0
    fi
    return 1
}

# Setup LUKS encryption
setup_luks() {
    log "Setting up LUKS encryption..."
    
    # Check if running on live system
    if [[ ! -f /etc/fstab ]]; then
        error "This script should be run during installation"
    fi
    
    # Create LUKS key file
    local keyfile="/root/.luks-keyfile"
    if [[ ! -f "$keyfile" ]]; then
        dd if=/dev/urandom of="$keyfile" bs=4096 count=1
        chmod 600 "$keyfile"
    fi
    
    # Setup crypttab
    if [[ ! -f /etc/crypttab ]]; then
        cat > /etc/crypttab << EOF
# <target name> <source device> <key file> <options>
cryptroot UUID=$(blkid -o value -s UUID /dev/sda3) $keyfile luks,discard
EOF
    fi
    
    # Update initramfs
    update-initramfs -u -k all
}

# Configure encrypted swap
setup_encrypted_swap() {
    log "Setting up encrypted swap..."
    
    # Check if swap exists
    if ! grep -q swap /etc/fstab; then
        log "No swap partition found"
        return
    fi
    
    # Add swap encryption to crypttab
    echo "cryptswap UUID=$(blkid -o value -s UUID /dev/sda2) /dev/urandom swap,cipher=aes-xts-plain64,size=512" >> /etc/crypttab
    
    # Update fstab
    sed -i 's|/dev/.*swap|/dev/mapper/cryptswap|' /etc/fstab
}

# Setup secure boot
setup_secure_boot() {
    log "Configuring secure boot..."
    
    # Check if UEFI mode
    if [[ ! -d /sys/firmware/efi ]]; then
        log "System not in UEFI mode, skipping secure boot"
        return
    fi
    
    # Install shim-signed
    apt-get install -y shim-signed grub-efi-amd64-signed
    
    # Update GRUB
    cat >> /etc/default/grub << EOF

# Security hardening
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash apparmor=1 security=apparmor"
GRUB_CMDLINE_LINUX="init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1"
EOF
    
    update-grub
}

# Configure boot partition encryption
setup_boot_encryption() {
    log "Setting up boot partition encryption..."
    
    # Check if separate /boot exists
    if ! mountpoint -q /boot; then
        log "No separate /boot partition"
        return
    fi
    
    # Add boot to crypttab
    local boot_uuid=$(blkid -o value -s UUID /dev/sda2)
    echo "cryptboot UUID=$boot_uuid none luks" >> /etc/crypttab
    
    # Create hook for boot decryption
    cat > /etc/initramfs-tools/hooks/decrypt_boot << 'EOF'
#!/bin/sh
case $1 in
    prereqs)
        echo ""
        exit 0
        ;;
esac

. /usr/share/initramfs-tools/hook-functions
copy_exec /sbin/cryptsetup
copy_exec /lib/cryptsetup/askpass
EOF
    
    chmod +x /etc/initramfs-tools/hooks/decrypt_boot
    update-initramfs -u
}

# Setup emergency wipe
setup_emergency_wipe() {
    log "Setting up emergency wipe capability..."
    
    cat > /usr/local/bin/emergency-wipe << 'EOF'
#!/bin/bash
# Emergency data wipe script

echo "EMERGENCY WIPE INITIATED!"
echo "This will destroy all data. Press Ctrl+C to cancel."
sleep 5

# Wipe swap
swapoff -a
if [[ -b /dev/mapper/cryptswap ]]; then
    dd if=/dev/urandom of=/dev/mapper/cryptswap bs=1M status=progress
fi

# Wipe LUKS headers
for dev in $(lsblk -o NAME,FSTYPE | grep crypto_LUKS | awk '{print $1}'); do
    cryptsetup luksErase --batch-mode "/dev/$dev"
done

# Wipe boot sectors
dd if=/dev/urandom of=/dev/sda bs=512 count=4096

echo "Emergency wipe complete. System is now unbootable."
EOF
    
    chmod 700 /usr/local/bin/emergency-wipe
}

# Main execution
main() {
    if [[ "$DISK_ENCRYPTION" != "yes" ]]; then
        log "Disk encryption disabled in configuration"
        return 0
    fi
    
    if check_encryption_status; then
        log "Encryption already configured"
    else
        setup_luks
        setup_encrypted_swap
    fi
    
    setup_secure_boot
    setup_boot_encryption
    setup_emergency_wipe
    
    log "Disk encryption setup complete"
}

main
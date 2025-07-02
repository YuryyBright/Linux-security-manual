#!/bin/bash
# Anonymity and Privacy Tools Setup

set -euo pipefail
source "$(dirname "$0")/../config/variables.conf"

log() { echo "[ANON] $1"; }

# Configure system-wide Tor usage
setup_tor_system() {
    log "Configuring system-wide Tor usage..."
    
    # Create torify wrapper
    cat > /usr/local/bin/torify-system << 'EOF'
#!/bin/bash
# System-wide torification

export ALL_PROXY="socks5://127.0.0.1:9050"
export http_proxy="socks5://127.0.0.1:9050"
export https_proxy="socks5://127.0.0.1:9050"
export ftp_proxy="socks5://127.0.0.1:9050"
export no_proxy="localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

exec "$@"
EOF
    chmod +x /usr/local/bin/torify-system
    
    # Create aliases
    cat >> /etc/bash.bashrc << 'EOF'

# Tor aliases
alias curl='torify-system curl'
alias wget='torify-system wget'
alias ssh='torify-system ssh'
alias git='torify-system git'
EOF
}

# Setup secure browser
setup_secure_browser() {
    log "Setting up secure browser configuration..."
    
    # Create Firefox profile
    local profile_dir="/etc/firefox/security-profile"
    mkdir -p "$profile_dir"
    
    # User preferences
    cat > "$profile_dir/user.js" << 'EOF'
// Privacy & Security Settings
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("browser.send_pings", false);
user_pref("browser.sessionstore.privacy_level", 2);
user_pref("browser.urlbar.speculativeConnect.enabled", false);

// Disable telemetry
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);

// Disable WebRTC
user_pref("media.peerconnection.enabled", false);
user_pref("media.navigator.enabled", false);

// Disable location
user_pref("geo.enabled", false);
user_pref("geo.wifi.uri", "");

// Disable WebGL
user_pref("webgl.disabled", true);

// Cookie settings
user_pref("network.cookie.cookieBehavior", 1);
user_pref("network.cookie.lifetimePolicy", 2);

// Disable JavaScript (optional)
user_pref("javascript.enabled", false);

// HTTPS only
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);

// DNS over HTTPS
user_pref("network.trr.mode", 3);
user_pref("network.trr.uri", "https://cloudflare-dns.com/dns-query");

// Disable prefetching
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("network.predictor.enabled", false);

// Disable cache
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.memory.enable", false);
user_pref("browser.cache.offline.enable", false);
EOF
    
    # Create launcher script
    cat > /usr/local/bin/secure-browser << 'EOF'
#!/bin/bash
# Launch secure browser

# Use Tor proxy
export ALL_PROXY="socks5://127.0.0.1:9050"

# Random user agent
AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
)
RANDOM_AGENT=${AGENTS[$RANDOM % ${#AGENTS[@]}]}

# Launch with security profile
firefox \
    --new-instance \
    --profile /etc/firefox/security-profile \
    --no-remote \
    --private-window \
    "$@"
EOF
    chmod +x /usr/local/bin/secure-browser
}

# Configure privacy tools
setup_privacy_tools() {
    log "Installing privacy tools..."
    
    # BleachBit for secure deletion
    apt-get install -y bleachbit
    
    # Create secure delete wrapper
    cat > /usr/local/bin/secure-delete << 'EOF'
#!/bin/bash
# Secure file deletion

if [[ $# -eq 0 ]]; then
    echo "Usage: secure-delete <file1> [file2] ..."
    exit 1
fi

for file in "$@"; do
    if [[ -f "$file" ]]; then
        echo "Securely deleting: $file"
        shred -vfz -n 7 "$file"
    else
        echo "File not found: $file"
    fi
done
EOF
    chmod +x /usr/local/bin/secure-delete
    
    # Create privacy cleanup script
    cat > /usr/local/bin/privacy-cleanup << 'EOF'
#!/bin/bash
# Privacy cleanup script

echo "Starting privacy cleanup..."

# Clear bash history
history -c
history -w
cat /dev/null > ~/.bash_history

# Clear system logs
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;

# Clear temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*

# Clear cache
sync && echo 3 > /proc/sys/vm/drop_caches

# Clear swap
swapoff -a && swapon -a

echo "Privacy cleanup complete"
EOF
    chmod +x /usr/local/bin/privacy-cleanup
}

# Setup encrypted containers
setup_encrypted_containers() {
    log "Setting up encrypted container support..."
    
    # Install VeraCrypt
    if [[ ! -f /usr/bin/veracrypt ]]; then
        wget -q https://launchpad.net/veracrypt/trunk/1.25.9/+download/veracrypt-1.25.9-Ubuntu-22.04-amd64.deb
        dpkg -i veracrypt-1.25.9-Ubuntu-22.04-amd64.deb || apt-get -f install -y
        rm veracrypt-1.25.9-Ubuntu-22.04-amd64.deb
    fi
    
    # Create container management script
    cat > /usr/local/bin/container-manager << 'EOF'
#!/bin/bash
# Encrypted container manager

case "$1" in
    create)
        if [[ -z "$2" || -z "$3" ]]; then
            echo "Usage: container-manager create <file> <size_in_MB>"
            exit 1
        fi
        veracrypt -t -c --volume-type=normal --size="${3}M" --encryption=AES \
            --hash=SHA-512 --filesystem=ext4 --pim=0 --keyfiles="" \
            --random-source=/dev/urandom "$2"
        ;;
    mount)
        if [[ -z "$2" || -z "$3" ]]; then
            echo "Usage: container-manager mount <file> <mountpoint>"
            exit 1
        fi
        veracrypt -t -k "" --pim=0 --protect-hidden=no "$2" "$3"
        ;;
    unmount)
        if [[ -z "$2" ]]; then
            echo "Usage: container-manager unmount <mountpoint>"
            exit 1
        fi
        veracrypt -d "$2"
        ;;
    *)
        echo "Usage: container-manager {create|mount|unmount}"
        exit 1
        ;;
esac
EOF
    chmod +x /usr/local/bin/container-manager
}

# Configure metadata removal
setup_metadata_removal() {
    log "Setting up metadata removal tools..."
    
    # Install MAT2 (Metadata Anonymisation Toolkit)
    apt-get install -y mat2
    
    # Create metadata cleaning script
    cat > /usr/local/bin/clean-metadata << 'EOF'
#!/bin/bash
# Remove metadata from files

if [[ $# -eq 0 ]]; then
    echo "Usage: clean-metadata <file1> [file2] ..."
    exit 1
fi

for file in "$@"; do
    if [[ -f "$file" ]]; then
        echo "Cleaning metadata from: $file"
        mat2 "$file"
    else
        echo "File not found: $file"
    fi
done
EOF
    chmod +x /usr/local/bin/clean-metadata
    
    # Auto-clean downloads
    cat > /usr/local/bin/watch-downloads << 'EOF'
#!/bin/bash
# Monitor and clean downloads

DOWNLOAD_DIR="$HOME/Downloads"
inotifywait -m -e create -e moved_to "$DOWNLOAD_DIR" |
while read path action file; do
    if [[ -f "$path$file" ]]; then
        sleep 1
        mat2 "$path$file" 2>/dev/null || true
    fi
done
EOF
    chmod +x /usr/local/bin/watch-downloads
}

# Setup anti-forensics
setup_anti_forensics() {
    log "Setting up anti-forensics measures..."
    
    # Disable swap file
    if [[ "$SECURITY_LEVEL" == "maximum" ]]; then
        swapoff -a
        sed -i '/ swap / s/^/#/' /etc/fstab
    fi
    
    # Configure secure memory wiping
    cat > /etc/sysctl.d/10-security-memory.conf << 'EOF'
# Memory security
vm.mmap_min_addr = 65536
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
kernel.yama.ptrace_scope = 2
kernel.core_pattern = |/bin/false
EOF
    sysctl -p /etc/sysctl.d/10-security-memory.conf
    
    # Create panic button script
    cat > /usr/local/bin/panic-button << 'EOF'
#!/bin/bash
# Emergency system wipe

echo "PANIC MODE ACTIVATED!"
echo "Press Ctrl+C within 5 seconds to cancel..."
sleep 5

# Kill all user processes
pkill -KILL -u $(whoami)

# Clear memory
echo 3 > /proc/sys/vm/drop_caches
smem-secure-delete

# Wipe temporary files
find /tmp -type f -exec shred -vfz -n 3 {} \;
find /var/tmp -type f -exec shred -vfz -n 3 {} \;
find /dev/shm -type f -exec shred -vfz -n 3 {} \;

# Clear logs
find /var/log -type f -exec truncate -s 0 {} \;

# If maximum security, initiate full wipe
if [[ "$1" == "--full" ]]; then
    /usr/local/bin/emergency-wipe
fi

# Shutdown
poweroff -f
EOF
    chmod 700 /usr/local/bin/panic-button
}

# Configure identity isolation
setup_identity_isolation() {
    log "Setting up identity isolation..."
    
    # Create isolated user environments
    cat > /usr/local/bin/create-identity << 'EOF'
#!/bin/bash
# Create isolated identity

if [[ -z "$1" ]]; then
    echo "Usage: create-identity <name>"
    exit 1
fi

IDENTITY="$1"
HOME_BASE="/home/identities"

# Create user
useradd -m -d "$HOME_BASE/$IDENTITY" -s /bin/bash "$IDENTITY"

# Setup isolated environment
su - "$IDENTITY" -c "
    # Configure Tor browser
    mkdir -p ~/.mozilla/firefox
    cp -r /etc/firefox/security-profile ~/.mozilla/firefox/
    
    # Create secure directories
    mkdir -p ~/Documents ~/Downloads
    chmod 700 ~/Documents
"

echo "Identity '$IDENTITY' created"
echo "Switch with: su - $IDENTITY"
EOF
    chmod +x /usr/local/bin/create-identity
}

# Setup secure communications
setup_secure_comms() {
    log "Setting up secure communication tools..."
    
    # Install Signal desktop
    wget -O- https://updates.signal.org/desktop/apt/keys.asc | gpg --dearmor > /usr/share/keyrings/signal-desktop-keyring.gpg
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/signal-desktop-keyring.gpg] https://updates.signal.org/desktop/apt xenial main' > /etc/apt/sources.list.d/signal-xenial.list
    apt-get update && apt-get install -y signal-desktop
    
    # Configure GPG for encrypted email
    cat > /etc/skel/.gnupg/gpg.conf << 'EOF'
# GPG Configuration
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
fixed-list-mode
no-comments
no-emit-version
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
require-cross-certification
no-symkey-cache
throw-keyids
use-agent
EOF
}

# Configure time anonymization
setup_time_anonymization() {
    log "Setting up time anonymization..."
    
    # Use UTC timezone
    timedatectl set-timezone UTC
    
    # Randomize system time slightly
    cat > /usr/local/bin/time-randomize << 'EOF'
#!/bin/bash
# Randomize time by a few seconds

OFFSET=$((RANDOM % 60 - 30))
date -s "$OFFSET seconds"
EOF
    chmod +x /usr/local/bin/time-randomize
    
    # Add to boot
    cat > /etc/systemd/system/time-randomize.service << 'EOF'
[Unit]
Description=Randomize system time
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/time-randomize

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable time-randomize.service
}

# Main execution
main() {
    setup_tor_system
    setup_secure_browser
    setup_privacy_tools
    setup_encrypted_containers
    setup_metadata_removal
    setup_anti_forensics
    setup_identity_isolation
    setup_secure_comms
    setup_time_anonymization
    
    log "Anonymity tools setup complete"
}

main
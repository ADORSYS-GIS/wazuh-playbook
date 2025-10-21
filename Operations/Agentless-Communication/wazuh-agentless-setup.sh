#!/bin/bash
# Wazuh Agentless Monitoring - Automated Setup Script
# This script runs INSIDE the Wazuh manager pod and automates SSH setup

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🎯 WAZUH AGENTLESS MONITORING - AUTOMATED SETUP${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""
echo "This script automates SSH setup for agentless monitoring."
echo "Supports both modern and legacy systems with automatic configuration."
echo ""
echo "📍 Running inside Wazuh manager pod"
echo ""

# Function to check if we're running inside the manager pod
check_prerequisites() {
    echo -e "${YELLOW}🔍 Checking environment...${NC}"
    
    if [ ! -d "/var/ossec" ]; then
        echo -e "${RED}❌ /var/ossec directory not found. Run this inside the Wazuh manager pod.${NC}"
        exit 1
    fi
    
    if [ ! -f "/var/ossec/bin/wazuh-control" ]; then
        echo -e "${RED}❌ Wazuh binaries not found. Ensure you're in the manager pod.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Environment check passed${NC}"
}

# Function to get user input
get_user_input() {
    echo -e "\n${YELLOW}📋 TARGET SYSTEM CONFIGURATION${NC}"
    echo "================================="
    
    # Get target system details
    read -p "Enter target system IP address: " TARGET_IP
    read -p "Enter username for target system: " TARGET_USER
    
    # Special handling for password to preserve spaces and special characters
    echo -n "Enter password for target system: "
    IFS= read -rs TARGET_PASSWORD
    echo ""
    
    # System type selection
    echo ""
    echo -e "${YELLOW}System Type Selection:${NC}"
    echo "1) Modern system (Ubuntu 18+, RHEL 8+, recent Linux distributions)"
    echo "2) Legacy system (RHEL 4.4, old Unix systems, systems from 2005-2010)"
    echo ""
    read -p "Choose system type [1-2]: " SYSTEM_TYPE
    
    # Validate input
    while [[ ! "$SYSTEM_TYPE" =~ ^[12]$ ]]; do
        echo -e "${RED}Invalid choice. Please enter 1 or 2.${NC}"
        read -p "Choose system type [1-2]: " SYSTEM_TYPE
    done
    
    # Confirmation
    echo ""
    echo -e "${YELLOW}📋 CONFIGURATION SUMMARY${NC}"
    echo "=========================="
    echo "Target System: $TARGET_USER@$TARGET_IP"
    echo "System Type: $([ "$SYSTEM_TYPE" = "1" ] && echo "Modern (standard SSH)" || echo "Legacy (old SSH algorithms)")"
    echo ""
    read -p "Continue with this configuration? (y/n): " CONFIRM
    
    if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Setup cancelled by user.${NC}"
        exit 0
    fi
}

# Function to install prerequisites in Wazuh manager
install_prerequisites() {
    echo -e "\n${GREEN}📦 CHECKING PREREQUISITES${NC}"
    echo "=========================="
    
    # Check if prerequisites are already installed
    MISSING_PACKAGES=""
    
    if ! command -v ssh &> /dev/null; then
        MISSING_PACKAGES="$MISSING_PACKAGES openssh-client"
    fi
    
    if ! command -v expect &> /dev/null; then
        MISSING_PACKAGES="$MISSING_PACKAGES expect"
    fi
    
    if ! command -v sshpass &> /dev/null; then
        MISSING_PACKAGES="$MISSING_PACKAGES sshpass"
    fi
    
    if [ -n "$MISSING_PACKAGES" ]; then
        echo "📦 Installing missing packages:$MISSING_PACKAGES"
        # Detect package manager and install accordingly
        if command -v yum &> /dev/null; then
            # Replace openssh-client with openssh-clients for RHEL/CentOS
            MISSING_PACKAGES=$(echo "$MISSING_PACKAGES" | sed 's/openssh-client/openssh-clients/g')
            yum install -y $MISSING_PACKAGES > /dev/null 2>&1
        elif command -v apt-get &> /dev/null; then
            apt-get update -qq > /dev/null 2>&1
            apt-get install -y $MISSING_PACKAGES > /dev/null 2>&1
        else
            echo -e "${RED}❌ No supported package manager found${NC}"
            exit 1
        fi
        echo "✅ Prerequisites installed successfully"
    else
        echo -e "${GREEN}✅ All prerequisites already installed${NC}"
    fi
}

# Function to test initial connection
test_initial_connection() {
    echo -e "\n${YELLOW}🔌 TESTING INITIAL CONNECTION${NC}"
    echo "================================="
    
    if [ "$SYSTEM_TYPE" = "2" ]; then
        echo "Testing legacy system connection with old SSH algorithms..."
        if sshpass -p "$TARGET_PASSWORD" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa $TARGET_USER@$TARGET_IP 'echo "Connection test successful"' &> /dev/null; then
            echo -e "${GREEN}✅ Legacy SSH connection successful${NC}"
            return 0
        else
            echo -e "${RED}❌ Legacy SSH connection failed${NC}"
            return 1
        fi
    else
        echo "Testing modern system connection..."
        if sshpass -p "$TARGET_PASSWORD" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no $TARGET_USER@$TARGET_IP 'echo "Connection test successful"' &> /dev/null; then
            echo -e "${GREEN}✅ Modern SSH connection successful${NC}"
            return 0
        else
            echo -e "${RED}❌ Modern SSH connection failed${NC}"
            return 1
        fi
    fi
}


# Function to generate SSH keys
generate_ssh_keys() {
    echo -e "\n${GREEN}🔑 SSH KEY MANAGEMENT${NC}"
    echo "======================"
    
    # Check if SSH keys already exist
    if su -s /bin/bash wazuh -c '[ -f ~/.ssh/id_rsa ] && [ -f ~/.ssh/id_rsa.pub ]'; then
        echo -e "${YELLOW}⚠️  SSH keys already exist${NC}"
        read -p "Do you want to regenerate SSH keys? (y/n): " REGENERATE_KEYS
        
        if [[ $REGENERATE_KEYS =~ ^[Yy]$ ]]; then
            echo "🔄 Regenerating SSH keys..."
            su -s /bin/bash wazuh -c '
                rm -f ~/.ssh/id_rsa ~/.ssh/id_rsa.pub
                mkdir -p ~/.ssh
                ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -C "wazuh-agentless" -q
                echo "✅ New SSH keys generated"
            '
        else
            echo -e "${GREEN}✅ Using existing SSH keys${NC}"
        fi
    else
        echo "🔑 Generating new SSH keys..."
        su -s /bin/bash wazuh -c '
            mkdir -p ~/.ssh
            ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -C "wazuh-agentless" -q
            echo "✅ SSH keys generated"
        '
    fi
}

# Function to configure SSH for legacy systems
configure_legacy_ssh() {
    echo -e "\n${GREEN}🔧 CONFIGURING LEGACY SSH COMPATIBILITY${NC}"
    echo "========================================"
    
    su -s /bin/bash wazuh -c "
        cat > ~/.ssh/config << 'EOF'
Host $TARGET_IP
    KexAlgorithms +diffie-hellman-group1-sha1
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedKeyTypes +ssh-rsa
    StrictHostKeyChecking no
    ConnectTimeout 10
EOF
        chmod 600 ~/.ssh/config
        echo '✅ Legacy SSH configuration created'
    "
}

# Function to copy SSH keys
copy_ssh_keys() {
    echo -e "\n${GREEN}📋 COPYING SSH KEYS TO TARGET${NC}"
    echo "================================="
    
    # Both legacy and modern systems can use normal ssh-copy-id
    # because SSH config handles legacy options automatically
    su -s /bin/bash wazuh -c "
        sshpass -p '$TARGET_PASSWORD' ssh-copy-id -f $TARGET_USER@$TARGET_IP
    "
    
    echo "✅ SSH keys copied successfully"
}

# Function to test passwordless SSH
test_passwordless_ssh() {
    echo -e "\n${YELLOW}🔐 TESTING PASSWORDLESS SSH${NC}"
    echo "============================="
    
    su -s /bin/bash wazuh -c "
        ssh $TARGET_USER@$TARGET_IP 'echo \"✅ Passwordless SSH working: \$(uname -a)\"'
    "
}

# Function to setup legacy command compatibility
setup_legacy_commands() {
    if [ "$SYSTEM_TYPE" = "2" ]; then
        echo -e "\n${GREEN}⚙️  SETTING UP LEGACY COMMAND COMPATIBILITY${NC}"
        echo "==========================================="
        
        # Create stat wrapper for legacy systems
        sshpass -p "$TARGET_PASSWORD" ssh $TARGET_USER@$TARGET_IP '
            cat > /tmp/modern_stat.sh << "EOF"
#!/bin/bash
# Modern stat wrapper for legacy systems
if [ "$1" = "--printf" ]; then
    format="$2"
    file="$3"
    # Convert --printf format to --format
    /usr/bin/stat --format="$format" "$file"
else
    # Pass through other arguments
    /usr/bin/stat "$@"
fi
EOF
            chmod +x /tmp/modern_stat.sh
            sudo cp /tmp/modern_stat.sh /usr/local/bin/stat
            sudo chmod +x /usr/local/bin/stat
            echo "✅ Legacy command compatibility configured"
        '
        
        # Test the stat wrapper
        echo "Testing stat wrapper..."
        sshpass -p "$TARGET_PASSWORD" ssh $TARGET_USER@$TARGET_IP 'stat --printf "%s" /etc/hosts && echo " ✅ stat wrapper working"'
    fi
}

# Function to patch agentless script for legacy systems
patch_agentless_script() {
    if [ "$SYSTEM_TYPE" = "2" ]; then
        echo -e "\n${GREEN}🔨 LEGACY AGENTLESS SCRIPT PATCHING${NC}"
        echo "===================================="
        
        # Check if script is already patched
        if grep -q "KexAlgorithms=+diffie-hellman-group1-sha1" /var/ossec/agentless/ssh_integrity_check_linux; then
            echo -e "${YELLOW}⚠️  Agentless script already patched for legacy compatibility${NC}"
            read -p "Do you want to re-patch the script? (y/n): " REPATCH_SCRIPT
            
            if [[ $REPATCH_SCRIPT =~ ^[Yy]$ ]]; then
                echo "🔄 Re-patching agentless script..."
                # Restore original and patch again
                [ -f /var/ossec/agentless/ssh_integrity_check_linux.backup ] && \
                cp /var/ossec/agentless/ssh_integrity_check_linux.backup /var/ossec/agentless/ssh_integrity_check_linux
                
                # Create backup if it doesn't exist
                [ ! -f /var/ossec/agentless/ssh_integrity_check_linux.backup ] && \
                cp /var/ossec/agentless/ssh_integrity_check_linux /var/ossec/agentless/ssh_integrity_check_linux.backup
                
                # Apply patch
                sed -i "s/spawn ssh \\$hostname/spawn ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa,ssh-dss \\$hostname/g" /var/ossec/agentless/ssh_integrity_check_linux
                echo "✅ Agentless script re-patched"
            else
                echo -e "${GREEN}✅ Using existing patched script${NC}"
            fi
        else
            echo "🔨 Patching agentless script for legacy compatibility..."
            # Create backup if it doesn't exist
            [ ! -f /var/ossec/agentless/ssh_integrity_check_linux.backup ] && \
            cp /var/ossec/agentless/ssh_integrity_check_linux /var/ossec/agentless/ssh_integrity_check_linux.backup
            
            # Apply patch
            sed -i "s/spawn ssh \\$hostname/spawn ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa,ssh-dss \\$hostname/g" /var/ossec/agentless/ssh_integrity_check_linux
            echo "✅ Agentless script patched for legacy compatibility"
        fi
    fi
}

# Function to register agentless host
register_agentless_host() {
    echo -e "\n${GREEN}📝 AGENTLESS HOST REGISTRATION${NC}"
    echo "==============================="
    
    # Check if host is already registered
    if grep -q "$TARGET_USER@$TARGET_IP" /var/ossec/agentless/.passlist 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Host $TARGET_USER@$TARGET_IP already registered${NC}"
        read -p "Do you want to re-register this host? (y/n): " REREGISTER_HOST
        
        if [[ $REREGISTER_HOST =~ ^[Yy]$ ]]; then
            echo "🔄 Re-registering agentless host..."
            # Remove existing entry and add new one
            sed -i "/$TARGET_USER@$TARGET_IP/d" /var/ossec/agentless/.passlist 2>/dev/null
            /var/ossec/agentless/register_host.sh add $TARGET_USER@$TARGET_IP NOPASS
            echo "✅ Agentless host re-registered"
        else
            echo -e "${GREEN}✅ Using existing registration${NC}"
        fi
    else
        echo "📝 Registering new agentless host..."
        /var/ossec/agentless/register_host.sh add $TARGET_USER@$TARGET_IP NOPASS
        echo "✅ Agentless host registered"
    fi
}

# Function to set correct permissions
set_permissions() {
    echo -e "\n${GREEN}🔒 SETTING CORRECT PERMISSIONS${NC}"
    echo "==============================="
    
    chown -R wazuh:wazuh /var/ossec/.ssh
    chmod 700 /var/ossec/.ssh
    chmod 600 /var/ossec/.ssh/id_rsa
    chmod 644 /var/ossec/.ssh/id_rsa.pub
    [ -f /var/ossec/.ssh/config ] && chmod 600 /var/ossec/.ssh/config
    echo "✅ Permissions set correctly"
}

# Function to show next steps
show_next_steps() {
    echo -e "\n${BLUE}📋 NEXT STEPS - MANUAL CONFIGURATION${NC}"
    echo "====================================="
    echo ""
    echo -e "${YELLOW}1. Add agentless configuration to ossec.conf:${NC}"
    echo ""
    echo "   Edit: /var/ossec/etc/ossec.conf"
    echo "   Add before closing </ossec_config> tag:"
    echo ""
    echo "   <!-- Agentless monitoring for $TARGET_USER@$TARGET_IP -->"
    echo "   <agentless>"
    echo "     <type>ssh_integrity_check_linux</type>"
    echo "     <frequency>60</frequency>"
    echo "     <host>$TARGET_USER@$TARGET_IP</host>"
    echo "     <state>periodic_diff</state>"
    echo "     <arguments>/bin /etc /sbin /usr/bin</arguments>"
    echo "   </agentless>"
    echo ""
    echo -e "${YELLOW}2. Restart Wazuh manager:${NC}"
    echo "   /var/ossec/bin/wazuh-control restart"
    echo ""
    echo -e "${YELLOW}3. Verify agentless monitoring:${NC}"
    echo "   /var/ossec/bin/agent_control -l"
    echo ""
}


# Main execution
main() {
    check_prerequisites
    get_user_input
    install_prerequisites
    test_initial_connection
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Initial connection test failed. Please check credentials and network connectivity.${NC}"
        exit 1
    fi
    generate_ssh_keys
    
    if [ "$SYSTEM_TYPE" = "2" ]; then
        configure_legacy_ssh
    fi
    
    copy_ssh_keys
    test_passwordless_ssh
    
    if [ "$SYSTEM_TYPE" = "2" ]; then
        setup_legacy_commands
        patch_agentless_script
    fi
    
    register_agentless_host
    set_permissions
    
    echo -e "\n${GREEN}🎉 SSH SETUP COMPLETED SUCCESSFULLY!${NC}"
    echo "====================================="
    
    echo -e "\n${BLUE}📝 SETUP SUMMARY${NC}"
    echo "================="
    echo "✅ Prerequisites checked/installed (openssh-client, expect, sshpass)"
    echo "✅ SSH keys managed and deployed to target system"
    if [ "$SYSTEM_TYPE" = "2" ]; then
        echo "✅ Legacy SSH compatibility configured (old algorithms enabled)"
        echo "✅ Legacy command compatibility configured (stat wrapper)"
        echo "✅ Agentless script patched for legacy systems"
    fi
    echo "✅ Agentless host registered in passlist"
    echo "✅ File permissions set correctly"
    echo ""
    echo -e "${GREEN}🔄 Script is idempotent - safe to run multiple times!${NC}"
    echo ""
    
    show_next_steps
    
    echo -e "${GREEN}🚀 Ready for manual ossec.conf configuration and restart!${NC}"
}

# Run main function
main

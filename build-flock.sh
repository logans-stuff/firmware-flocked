#!/bin/bash
#
# Flock-You Meshtastic Firmware Build Script for Ubuntu
# Builds surveillance detection firmware for T-Beam Supreme (tbeam-s3-core)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TARGET="${1:-tbeam-s3-core}"
ACTION="${2:-build}"

echo -e "${GREEN}=======================================${NC}"
echo -e "${GREEN} Flock-You Meshtastic Firmware Builder ${NC}"
echo -e "${GREEN}=======================================${NC}"
echo ""
echo "Target: $TARGET"
echo "Action: $ACTION"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies
install_dependencies() {
    echo -e "${YELLOW}[1/4] Installing system dependencies...${NC}"

    sudo apt-get update
    sudo apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        git \
        curl \
        wget \
        libffi-dev \
        libssl-dev \
        libudev-dev \
        pkg-config

    echo -e "${GREEN}System dependencies installed.${NC}"
}

# Install PlatformIO
install_platformio() {
    echo -e "${YELLOW}[2/4] Installing PlatformIO...${NC}"

    if command_exists pio; then
        echo "PlatformIO already installed: $(pio --version)"
    else
        # Install PlatformIO Core
        curl -fsSL -o get-platformio.py https://raw.githubusercontent.com/platformio/platformio-core-installer/master/get-platformio.py
        python3 get-platformio.py
        rm -f get-platformio.py

        # Add to PATH for current session
        export PATH="$PATH:$HOME/.platformio/penv/bin"

        # Add to bashrc if not already there
        if ! grep -q "platformio/penv/bin" ~/.bashrc 2>/dev/null; then
            echo 'export PATH="$PATH:$HOME/.platformio/penv/bin"' >> ~/.bashrc
        fi
    fi

    echo -e "${GREEN}PlatformIO installed.${NC}"
}

# Setup udev rules for USB access (needed for flashing)
setup_udev() {
    echo -e "${YELLOW}[3/4] Setting up USB access rules...${NC}"

    # Create udev rules for common ESP32 USB chips
    RULES_FILE="/etc/udev/rules.d/99-platformio-udev.rules"

    if [ ! -f "$RULES_FILE" ]; then
        sudo tee "$RULES_FILE" > /dev/null << 'EOF'
# CP210x
ATTRS{idVendor)}=="10c4", ATTRS{idProduct}=="ea60", MODE="0666", GROUP="plugdev"
# CH340/CH341
ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7523", MODE="0666", GROUP="plugdev"
ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="55d4", MODE="0666", GROUP="plugdev"
# FTDI
ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6001", MODE="0666", GROUP="plugdev"
ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6010", MODE="0666", GROUP="plugdev"
ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6015", MODE="0666", GROUP="plugdev"
# ESP32-S3 native USB
ATTRS{idVendor}=="303a", ATTRS{idProduct}=="1001", MODE="0666", GROUP="plugdev"
ATTRS{idVendor}=="303a", ATTRS{idProduct}=="80*",  MODE="0666", GROUP="plugdev"
EOF
        sudo udevadm control --reload-rules
        sudo udevadm trigger

        # Add user to plugdev and dialout groups
        sudo usermod -a -G plugdev,dialout $USER

        echo -e "${YELLOW}NOTE: You may need to log out and back in for USB permissions to take effect.${NC}"
    fi

    echo -e "${GREEN}USB rules configured.${NC}"
}

# Build firmware
build_firmware() {
    echo -e "${YELLOW}[4/4] Building firmware for $TARGET...${NC}"

    # Ensure we're in the right directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    # Make sure pio is in PATH
    export PATH="$PATH:$HOME/.platformio/penv/bin"

    # Clean previous build (optional)
    if [ "$ACTION" == "clean" ]; then
        echo "Cleaning previous build..."
        pio run -e "$TARGET" -t clean
    fi

    # Build
    echo "Building..."
    pio run -e "$TARGET"

    # Show output location
    FIRMWARE_BIN=".pio/build/$TARGET/firmware.bin"
    if [ -f "$FIRMWARE_BIN" ]; then
        echo ""
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN} BUILD SUCCESSFUL!${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo ""
        echo "Firmware binary: $FIRMWARE_BIN"
        echo "Size: $(du -h "$FIRMWARE_BIN" | cut -f1)"
        echo ""
        echo "To flash to device:"
        echo "  ./build-flock.sh $TARGET flash"
        echo ""
        echo "Or manually:"
        echo "  pio run -e $TARGET -t upload"
        echo ""
    else
        echo -e "${RED}Build failed - firmware not found${NC}"
        exit 1
    fi
}

# Flash firmware
flash_firmware() {
    echo -e "${YELLOW}Flashing firmware to device...${NC}"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    export PATH="$PATH:$HOME/.platformio/penv/bin"

    # Check for connected device
    echo "Looking for device..."

    # Try to flash
    pio run -e "$TARGET" -t upload

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN} FLASH COMPLETE!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Next steps to enable flock detection:"
    echo ""
    echo "1. Connect to device via Meshtastic app or CLI"
    echo "2. Disable WiFi:     meshtastic --set network.wifi_enabled false"
    echo "3. Disable Bluetooth: meshtastic --set bluetooth.enabled false"
    echo "   (Note: after disabling BT, use USB serial to communicate)"
    echo ""
    echo "The FlockModule will automatically start scanning once"
    echo "WiFi and/or Bluetooth are disabled."
    echo ""
}

# Monitor serial output
monitor_serial() {
    echo -e "${YELLOW}Starting serial monitor...${NC}"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    export PATH="$PATH:$HOME/.platformio/penv/bin"

    pio device monitor -b 115200
}

# Main execution
case "$ACTION" in
    "setup")
        install_dependencies
        install_platformio
        setup_udev
        echo ""
        echo -e "${GREEN}Setup complete! Run './build-flock.sh' to build.${NC}"
        ;;
    "build")
        # Check if pio exists, if not run setup first
        if ! command_exists pio && [ ! -f "$HOME/.platformio/penv/bin/pio" ]; then
            echo "PlatformIO not found. Running setup first..."
            install_dependencies
            install_platformio
            setup_udev
        fi
        build_firmware
        ;;
    "flash")
        build_firmware
        flash_firmware
        ;;
    "upload")
        flash_firmware
        ;;
    "monitor")
        monitor_serial
        ;;
    "clean")
        export PATH="$PATH:$HOME/.platformio/penv/bin"
        pio run -e "$TARGET" -t clean
        echo -e "${GREEN}Clean complete.${NC}"
        ;;
    "all")
        install_dependencies
        install_platformio
        setup_udev
        build_firmware
        ;;
    *)
        echo "Usage: $0 [target] [action]"
        echo ""
        echo "Targets:"
        echo "  tbeam-s3-core    T-Beam Supreme (default)"
        echo "  tbeam            T-Beam v1.x (ESP32)"
        echo "  tbeam_v07        T-Beam v0.7"
        echo "  (or any other valid PlatformIO environment)"
        echo ""
        echo "Actions:"
        echo "  setup    Install dependencies and PlatformIO"
        echo "  build    Build firmware (default)"
        echo "  flash    Build and flash to device"
        echo "  upload   Flash only (no rebuild)"
        echo "  monitor  Open serial monitor"
        echo "  clean    Clean build files"
        echo "  all      Setup + build"
        echo ""
        echo "Examples:"
        echo "  $0                        # Build for T-Beam Supreme"
        echo "  $0 tbeam-s3-core setup    # Install dependencies"
        echo "  $0 tbeam-s3-core flash    # Build and flash"
        echo "  $0 tbeam-s3-core monitor  # Watch serial output"
        echo ""
        ;;
esac

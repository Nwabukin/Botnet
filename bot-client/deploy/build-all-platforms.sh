#!/bin/bash

# Cross-platform build script for botnet client
# FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
DEPLOY_DIR="$PROJECT_ROOT/deploy/packages"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Botnet Client Cross-Platform Builder  ${NC}"
echo -e "${BLUE}    FOR RESEARCH PURPOSES ONLY          ${NC}"
echo -e "${BLUE}========================================${NC}"

# Check if Docker is available for cross-compilation
check_docker() {
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}✓ Docker found - cross-compilation available${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Docker not found - local compilation only${NC}"
        return 1
    fi
}

# Clean previous builds
clean_builds() {
    echo -e "${YELLOW}Cleaning previous builds...${NC}"
    rm -rf "$BUILD_DIR"
    rm -rf "$DEPLOY_DIR"
    mkdir -p "$DEPLOY_DIR"
}

# Build for current platform
build_native() {
    echo -e "${BLUE}Building for native platform...${NC}"
    
    cd "$PROJECT_ROOT"
    mkdir -p "$BUILD_DIR/native"
    cd "$BUILD_DIR/native"
    
    cmake -DCMAKE_BUILD_TYPE=Release "$PROJECT_ROOT"
    make -j$(nproc)
    make package
    
    # Copy package to deploy directory
    cp *.tar.gz "$DEPLOY_DIR/"
    echo -e "${GREEN}✓ Native build completed${NC}"
}

# Build for Windows using Docker
build_windows() {
    if ! check_docker; then
        echo -e "${YELLOW}Skipping Windows build (Docker required)${NC}"
        return
    fi
    
    echo -e "${BLUE}Building for Windows (x64)...${NC}"
    
    docker run --rm \
        -v "$PROJECT_ROOT:/src" \
        -v "$DEPLOY_DIR:/deploy" \
        -w /src \
        dockcross/windows-static-x64 \
        bash -c "
            mkdir -p build/windows
            cd build/windows
            cmake -DCMAKE_BUILD_TYPE=Release \
                  -DCMAKE_TOOLCHAIN_FILE=/usr/xcc/cmake/toolchain.cmake \
                  /src
            make -j\$(nproc)
            make package
            cp *.tar.gz /deploy/
        "
    
    echo -e "${GREEN}✓ Windows build completed${NC}"
}

# Build for Linux using Docker
build_linux() {
    if ! check_docker; then
        echo -e "${YELLOW}Skipping Linux build (Docker required)${NC}"
        return
    fi
    
    echo -e "${BLUE}Building for Linux (x64)...${NC}"
    
    docker run --rm \
        -v "$PROJECT_ROOT:/src" \
        -v "$DEPLOY_DIR:/deploy" \
        -w /src \
        dockcross/linux-x64 \
        bash -c "
            mkdir -p build/linux
            cd build/linux
            cmake -DCMAKE_BUILD_TYPE=Release \
                  -DCMAKE_TOOLCHAIN_FILE=/usr/xcc/cmake/toolchain.cmake \
                  /src
            make -j\$(nproc)
            make package
            cp *.tar.gz /deploy/
        "
    
    echo -e "${GREEN}✓ Linux build completed${NC}"
}

# Build for macOS using Docker (if available)
build_macos() {
    if ! check_docker; then
        echo -e "${YELLOW}Skipping macOS build (Docker required)${NC}"
        return
    fi
    
    echo -e "${BLUE}Building for macOS (x64)...${NC}"
    
    # Note: macOS cross-compilation requires additional setup
    echo -e "${YELLOW}macOS cross-compilation requires osxcross setup${NC}"
    echo -e "${YELLOW}For now, build natively on macOS or use GitHub Actions${NC}"
}

# Create Windows installer
create_windows_installer() {
    if [ ! -f "$DEPLOY_DIR/botnet-client-windows-"*.tar.gz ]; then
        echo -e "${YELLOW}No Windows package found, skipping installer creation${NC}"
        return
    fi
    
    echo -e "${BLUE}Creating Windows installer...${NC}"
    
    # Extract Windows package
    cd "$DEPLOY_DIR"
    tar -xzf botnet-client-windows-*.tar.gz
    
    # Use NSIS to create installer (if available)
    if command -v makensis &> /dev/null; then
        makensis "$PROJECT_ROOT/installers/windows/installer.nsi"
        echo -e "${GREEN}✓ Windows installer created${NC}"
    else
        echo -e "${YELLOW}NSIS not found, skipping installer creation${NC}"
    fi
}

# Create Linux packages
create_linux_packages() {
    if [ ! -f "$DEPLOY_DIR/botnet-client-linux-"*.tar.gz ]; then
        echo -e "${YELLOW}No Linux package found, skipping package creation${NC}"
        return
    fi
    
    echo -e "${BLUE}Creating Linux packages...${NC}"
    
    cd "$DEPLOY_DIR"
    tar -xzf botnet-client-linux-*.tar.gz
    
    # Create DEB package (if fpm is available)
    if command -v fpm &> /dev/null; then
        fpm -s dir -t deb -n botnet-client -v 1.0.0 \
            --description "Botnet Client for Research" \
            --license "Educational Use Only" \
            --vendor "Research Project" \
            botnet-client-linux-*/=/opt/botnet-client/
        
        echo -e "${GREEN}✓ DEB package created${NC}"
    else
        echo -e "${YELLOW}fpm not found, skipping DEB package creation${NC}"
    fi
}

# Generate checksums
generate_checksums() {
    echo -e "${BLUE}Generating checksums...${NC}"
    
    cd "$DEPLOY_DIR"
    find . -name "*.tar.gz" -o -name "*.exe" -o -name "*.deb" | while read file; do
        sha256sum "$file" >> checksums.sha256
    done
    
    echo -e "${GREEN}✓ Checksums generated${NC}"
}

# Main build process
main() {
    echo -e "${YELLOW}Starting cross-platform build process...${NC}"
    
    # Parse command line arguments
    BUILD_ALL=true
    BUILD_NATIVE_ONLY=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --native-only)
                BUILD_NATIVE_ONLY=true
                BUILD_ALL=false
                shift
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --native-only    Build for current platform only"
                echo "  --help          Show this help message"
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                exit 1
                ;;
        esac
    done
    
    clean_builds
    
    if [ "$BUILD_NATIVE_ONLY" = true ]; then
        build_native
    elif [ "$BUILD_ALL" = true ]; then
        build_native
        build_windows
        build_linux
        build_macos
        
        # Create platform-specific packages
        create_windows_installer
        create_linux_packages
    fi
    
    generate_checksums
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Build process completed successfully!  ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "${BLUE}Packages available in: $DEPLOY_DIR${NC}"
    ls -la "$DEPLOY_DIR"
    
    echo -e "${YELLOW}⚠️  REMEMBER: FOR RESEARCH PURPOSES ONLY${NC}"
    echo -e "${YELLOW}   Use responsibly and ethically!${NC}"
}

# Run main function
main "$@"

#!/usr/bin/env bash
#
# TR4C3R Portable Build Script
# Creates self-contained portable packages for Windows, macOS, and Linux
#
# Usage:
#   ./scripts/build-portable.sh                    # Build for current platform
#   ./scripts/build-portable.sh --platform all     # Build for all platforms
#   ./scripts/build-portable.sh --platform windows # Build for Windows only
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/portable"
RELEASE_DIR="$PROJECT_ROOT/releases"
VERSION="1.0.0"
PYTHON_VERSION="3.11.9"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect current platform
detect_platform() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "macos";;
        CYGWIN*|MINGW*|MSYS*) echo "windows";;
        *)          echo "unknown";;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x64";;
        arm64|aarch64)  echo "arm64";;
        *)              echo "x64";;
    esac
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check for Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
    fi
    
    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required but not installed"
    fi
    
    # Check for PyInstaller
    if ! python3 -c "import PyInstaller" 2>/dev/null; then
        log_warning "PyInstaller not found, installing..."
        pip3 install pyinstaller
    fi
    
    log_success "All dependencies satisfied"
}

# Clean build directory
clean_build() {
    log_info "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    mkdir -p "$RELEASE_DIR"
}

# Create PyInstaller spec file
create_spec_file() {
    local platform=$1
    local spec_file="$BUILD_DIR/tr4c3r.spec"
    
    log_info "Creating PyInstaller spec for $platform..."
    
    # Determine icon based on platform
    local icon_option=""
    if [ "$platform" = "windows" ]; then
        icon_option="icon='$PROJECT_ROOT/docs/assets/icon.ico',"
    elif [ "$platform" = "macos" ]; then
        icon_option="icon='$PROJECT_ROOT/docs/assets/icon.icns',"
    fi
    
    cat > "$spec_file" << EOF
# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from pathlib import Path

block_cipher = None

# Project paths
project_root = Path('$PROJECT_ROOT')
src_path = project_root / 'src'

# Collect all source files
def collect_source_files():
    data_files = []
    for root, dirs, files in os.walk(src_path):
        # Skip __pycache__
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for file in files:
            if file.endswith('.py'):
                src = os.path.join(root, file)
                dst = os.path.relpath(root, project_root)
                data_files.append((src, dst))
    return data_files

# Hidden imports for dynamic modules
hidden_imports = [
    'src',
    'src.cli',
    'src.api',
    'src.api.main',
    'src.api.mobile',
    'src.core',
    'src.core.batch_search',
    'src.core.cache',
    'src.core.config',
    'src.core.correlation',
    'src.core.deduplication',
    'src.core.graph_exporter',
    'src.core.notifications',
    'src.core.reports',
    'src.core.scheduler',
    'src.core.tagging',
    'src.search',
    'src.search.username',
    'src.search.email',
    'src.search.phone',
    'src.search.name',
    'src.search.social',
    'src.search.darkweb',
    'src.security',
    'src.security.auth',
    'src.security.advisor',
    'src.security.encryption',
    'src.storage',
    'src.visualization',
    'src.integrations',
    'src.integrations.threat_intel',
    'src.utils',
    'src.models',
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'fastapi',
    'starlette',
    'pydantic',
    'httpx',
    'aiohttp',
    'cryptography',
    'jwt',
    'pyotp',
    'apscheduler',
    'jinja2',
    'yaml',
    'sqlite3',
    'json',
    'csv',
    'xml.etree.ElementTree',
]

# Data files to include
datas = [
    ('$PROJECT_ROOT/config', 'config'),
    ('$PROJECT_ROOT/lib', 'lib'),
    ('$PROJECT_ROOT/docs', 'docs'),
]

# Add source files
for src_file, dst_dir in collect_source_files():
    datas.append((src_file, dst_dir))

a = Analysis(
    ['$PROJECT_ROOT/src/cli.py'],
    pathex=['$PROJECT_ROOT'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='tr4c3r',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    $icon_option
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='tr4c3r',
)
EOF
    
    log_success "Spec file created"
}

# Build for specific platform
build_platform() {
    local platform=$1
    local arch=$2
    local output_name="tr4c3r-${VERSION}-${platform}-${arch}"
    local output_dir="$BUILD_DIR/$output_name"
    
    log_info "Building for $platform-$arch..."
    
    # Create spec file
    create_spec_file "$platform"
    
    # Run PyInstaller
    cd "$PROJECT_ROOT"
    python3 -m PyInstaller \
        --distpath "$BUILD_DIR/dist" \
        --workpath "$BUILD_DIR/work" \
        --specpath "$BUILD_DIR" \
        --clean \
        "$BUILD_DIR/tr4c3r.spec"
    
    # Move to output directory
    mv "$BUILD_DIR/dist/tr4c3r" "$output_dir"
    
    # Create data directories
    mkdir -p "$output_dir/data"
    mkdir -p "$output_dir/logs"
    mkdir -p "$output_dir/config"
    
    # Copy default config
    if [ -f "$PROJECT_ROOT/config/tr4c3r.yaml.example" ]; then
        cp "$PROJECT_ROOT/config/tr4c3r.yaml.example" "$output_dir/config/tr4c3r.yaml"
    fi
    
    # Create launcher scripts
    create_launchers "$output_dir" "$platform"
    
    # Create portable marker file
    echo "TR4C3R Portable v$VERSION" > "$output_dir/.portable"
    echo "Built: $(date)" >> "$output_dir/.portable"
    echo "Platform: $platform-$arch" >> "$output_dir/.portable"
    
    # Package
    package_build "$output_dir" "$output_name" "$platform"
    
    log_success "Built $output_name"
}

# Create launcher scripts
create_launchers() {
    local output_dir=$1
    local platform=$2
    
    log_info "Creating launcher scripts..."
    
    if [ "$platform" = "windows" ]; then
        # Windows batch file
        cat > "$output_dir/start.bat" << 'EOF'
@echo off
setlocal enabledelayedexpansion

:: TR4C3R Portable Launcher for Windows
:: This script runs TR4C3R from a USB drive without installation

title TR4C3R - OSINT Platform

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Set environment variables for portable mode
set "TR4C3R_PORTABLE=1"
set "TR4C3R_DATA=%SCRIPT_DIR%data"
set "TR4C3R_LOGS=%SCRIPT_DIR%logs"
set "TR4C3R_CONFIG=%SCRIPT_DIR%config\tr4c3r.yaml"

:: Create directories if they don't exist
if not exist "%TR4C3R_DATA%" mkdir "%TR4C3R_DATA%"
if not exist "%TR4C3R_LOGS%" mkdir "%TR4C3R_LOGS%"

echo.
echo  ████████╗██████╗ ██╗  ██╗ ██████╗██████╗ ██████╗ 
echo  ╚══██╔══╝██╔══██╗██║  ██║██╔════╝╚════██╗██╔══██╗
echo     ██║   ██████╔╝███████║██║      █████╔╝██████╔╝
echo     ██║   ██╔══██╗╚════██║██║      ╚═══██╗██╔══██╗
echo     ██║   ██║  ██║     ██║╚██████╗██████╔╝██║  ██║
echo     ╚═╝   ╚═╝  ╚═╝     ╚═╝ ╚═════╝╚═════╝ ╚═╝  ╚═╝
echo.
echo  Advanced OSINT Platform - Portable Edition
echo  ============================================
echo.

:: Check if running with arguments
if "%~1"=="" (
    :: No arguments, show menu
    echo  Options:
    echo    1. Start CLI (interactive)
    echo    2. Start Web Dashboard
    echo    3. Run search (enter command)
    echo    4. Exit
    echo.
    set /p choice="  Select option (1-4): "
    
    if "!choice!"=="1" (
        "%SCRIPT_DIR%tr4c3r.exe" --help
        echo.
        echo Enter commands below (type 'exit' to quit):
        :cmd_loop
        set /p cmd="tr4c3r> "
        if /i "!cmd!"=="exit" goto :eof
        "%SCRIPT_DIR%tr4c3r.exe" !cmd!
        goto :cmd_loop
    ) else if "!choice!"=="2" (
        echo Starting web dashboard on http://localhost:8000
        echo Press Ctrl+C to stop
        "%SCRIPT_DIR%tr4c3r.exe" api --host 0.0.0.0 --port 8000
    ) else if "!choice!"=="3" (
        set /p cmd="Enter command: "
        "%SCRIPT_DIR%tr4c3r.exe" !cmd!
        pause
    ) else if "!choice!"=="4" (
        exit
    ) else (
        echo Invalid option
        pause
    )
) else (
    :: Run with provided arguments
    "%SCRIPT_DIR%tr4c3r.exe" %*
)

endlocal
EOF
        
        # Also create a simple runner
        cat > "$output_dir/tr4c3r-cli.bat" << 'EOF'
@echo off
"%~dp0tr4c3r.exe" %*
EOF

    else
        # Unix shell script (macOS/Linux)
        cat > "$output_dir/start.sh" << 'EOF'
#!/usr/bin/env bash
#
# TR4C3R Portable Launcher
# Runs TR4C3R from a USB drive without installation
#

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Set environment variables for portable mode
export TR4C3R_PORTABLE=1
export TR4C3R_DATA="$SCRIPT_DIR/data"
export TR4C3R_LOGS="$SCRIPT_DIR/logs"
export TR4C3R_CONFIG="$SCRIPT_DIR/config/tr4c3r.yaml"

# Create directories if they don't exist
mkdir -p "$TR4C3R_DATA"
mkdir -p "$TR4C3R_LOGS"

# Display banner
cat << 'BANNER'

 ████████╗██████╗ ██╗  ██╗ ██████╗██████╗ ██████╗ 
 ╚══██╔══╝██╔══██╗██║  ██║██╔════╝╚════██╗██╔══██╗
    ██║   ██████╔╝███████║██║      █████╔╝██████╔╝
    ██║   ██╔══██╗╚════██║██║      ╚═══██╗██╔══██╗
    ██║   ██║  ██║     ██║╚██████╗██████╔╝██║  ██║
    ╚═╝   ╚═╝  ╚═╝     ╚═╝ ╚═════╝╚═════╝ ╚═╝  ╚═╝

 Advanced OSINT Platform - Portable Edition
 ============================================

BANNER

# Check if running with arguments
if [ $# -eq 0 ]; then
    echo " Options:"
    echo "   1. Start CLI (interactive)"
    echo "   2. Start Web Dashboard"
    echo "   3. Run search (enter command)"
    echo "   4. Exit"
    echo ""
    read -p " Select option (1-4): " choice
    
    case $choice in
        1)
            "$SCRIPT_DIR/tr4c3r" --help
            echo ""
            echo "Enter commands below (type 'exit' to quit):"
            while true; do
                read -p "tr4c3r> " cmd
                if [ "$cmd" = "exit" ]; then
                    break
                fi
                "$SCRIPT_DIR/tr4c3r" $cmd
            done
            ;;
        2)
            echo "Starting web dashboard on http://localhost:8000"
            echo "Press Ctrl+C to stop"
            "$SCRIPT_DIR/tr4c3r" api --host 0.0.0.0 --port 8000
            ;;
        3)
            read -p "Enter command: " cmd
            "$SCRIPT_DIR/tr4c3r" $cmd
            ;;
        4)
            exit 0
            ;;
        *)
            echo "Invalid option"
            exit 1
            ;;
    esac
else
    # Run with provided arguments
    "$SCRIPT_DIR/tr4c3r" "$@"
fi
EOF
        chmod +x "$output_dir/start.sh"
        chmod +x "$output_dir/tr4c3r" 2>/dev/null || true
    fi
    
    log_success "Launcher scripts created"
}

# Package the build
package_build() {
    local output_dir=$1
    local output_name=$2
    local platform=$3
    
    log_info "Packaging $output_name..."
    
    cd "$BUILD_DIR"
    
    if [ "$platform" = "windows" ]; then
        # Create ZIP for Windows
        if command -v zip &> /dev/null; then
            zip -r "$RELEASE_DIR/${output_name}.zip" "$output_name"
        else
            log_warning "zip not found, skipping archive creation"
        fi
    else
        # Create tarball for Unix
        tar -czf "$RELEASE_DIR/${output_name}.tar.gz" "$output_name"
    fi
    
    log_success "Package created: $RELEASE_DIR/${output_name}.*"
}

# Main build function
main() {
    local platform="${1:-$(detect_platform)}"
    local arch=$(detect_arch)
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║        TR4C3R Portable Build System v$VERSION             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    
    check_dependencies
    clean_build
    
    case "$platform" in
        all)
            log_info "Building for all platforms..."
            build_platform "linux" "$arch"
            build_platform "macos" "$arch"
            # Note: Windows cross-compilation requires Wine + PyInstaller
            if [ "$(detect_platform)" = "windows" ]; then
                build_platform "windows" "$arch"
            else
                log_warning "Skipping Windows build (requires Windows or Wine)"
            fi
            ;;
        windows|macos|linux)
            build_platform "$platform" "$arch"
            ;;
        *)
            log_error "Unknown platform: $platform (use: windows, macos, linux, or all)"
            ;;
    esac
    
    echo ""
    log_success "Build complete! Packages available in: $RELEASE_DIR"
    ls -la "$RELEASE_DIR"
}

# Parse arguments
PLATFORM=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --platform|-p)
            PLATFORM="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--platform <platform>]"
            echo ""
            echo "Options:"
            echo "  --platform, -p    Target platform (windows, macos, linux, all)"
            echo "  --help, -h        Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            ;;
    esac
done

main "$PLATFORM"

@echo off
REM TR4C3R Portable Build Script for Windows
REM Creates self-contained portable package using PyInstaller

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "BUILD_DIR=%PROJECT_ROOT%\portable"
set "RELEASE_DIR=%PROJECT_ROOT%\releases"
set "VERSION=1.0.0"

echo.
echo ══════════════════════════════════════════════════════════
echo          TR4C3R Portable Build System v%VERSION%
echo ══════════════════════════════════════════════════════════
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is required but not installed
    exit /b 1
)
echo [INFO] Python found

REM Check/Install PyInstaller
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] PyInstaller not found, installing...
    pip install pyinstaller
)
echo [INFO] PyInstaller ready

REM Clean build directory
echo [INFO] Cleaning build directory...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"

REM Determine architecture
set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"

set "OUTPUT_NAME=tr4c3r-%VERSION%-windows-%ARCH%"
set "OUTPUT_DIR=%BUILD_DIR%\%OUTPUT_NAME%"

echo [INFO] Building for Windows-%ARCH%...

REM Create PyInstaller command
cd /d "%PROJECT_ROOT%"

python -m PyInstaller ^
    --name tr4c3r ^
    --distpath "%BUILD_DIR%\dist" ^
    --workpath "%BUILD_DIR%\work" ^
    --specpath "%BUILD_DIR%" ^
    --clean ^
    --onedir ^
    --console ^
    --noconfirm ^
    --add-data "config;config" ^
    --add-data "lib;lib" ^
    --add-data "docs;docs" ^
    --add-data "src;src" ^
    --hidden-import src ^
    --hidden-import src.cli ^
    --hidden-import src.api ^
    --hidden-import src.api.main ^
    --hidden-import src.core ^
    --hidden-import src.core.batch_search ^
    --hidden-import src.core.cache ^
    --hidden-import src.core.config ^
    --hidden-import src.core.correlation ^
    --hidden-import src.core.graph_exporter ^
    --hidden-import src.core.notifications ^
    --hidden-import src.core.reports ^
    --hidden-import src.core.scheduler ^
    --hidden-import src.core.tagging ^
    --hidden-import src.search ^
    --hidden-import src.security ^
    --hidden-import src.security.auth ^
    --hidden-import src.storage ^
    --hidden-import src.visualization ^
    --hidden-import src.integrations ^
    --hidden-import src.utils ^
    --hidden-import uvicorn ^
    --hidden-import fastapi ^
    --hidden-import starlette ^
    --hidden-import pydantic ^
    --hidden-import httpx ^
    --hidden-import cryptography ^
    --hidden-import yaml ^
    --hidden-import jinja2 ^
    --hidden-import apscheduler ^
    --collect-all src ^
    src\cli.py

if errorlevel 1 (
    echo [ERROR] PyInstaller build failed
    exit /b 1
)

REM Move to output directory
move "%BUILD_DIR%\dist\tr4c3r" "%OUTPUT_DIR%"

REM Create data directories
mkdir "%OUTPUT_DIR%\data"
mkdir "%OUTPUT_DIR%\logs"

REM Copy config
if exist "%PROJECT_ROOT%\config\tr4c3r.yaml.example" (
    copy "%PROJECT_ROOT%\config\tr4c3r.yaml.example" "%OUTPUT_DIR%\config\tr4c3r.yaml"
)

REM Create launcher
echo @echo off > "%OUTPUT_DIR%\start.bat"
echo setlocal enabledelayedexpansion >> "%OUTPUT_DIR%\start.bat"
echo set "SCRIPT_DIR=%%~dp0" >> "%OUTPUT_DIR%\start.bat"
echo set "TR4C3R_PORTABLE=1" >> "%OUTPUT_DIR%\start.bat"
echo set "TR4C3R_DATA=%%SCRIPT_DIR%%data" >> "%OUTPUT_DIR%\start.bat"
echo set "TR4C3R_LOGS=%%SCRIPT_DIR%%logs" >> "%OUTPUT_DIR%\start.bat"
echo set "TR4C3R_CONFIG=%%SCRIPT_DIR%%config\tr4c3r.yaml" >> "%OUTPUT_DIR%\start.bat"
echo "%%SCRIPT_DIR%%tr4c3r.exe" %%* >> "%OUTPUT_DIR%\start.bat"
echo endlocal >> "%OUTPUT_DIR%\start.bat"

REM Create portable marker
echo TR4C3R Portable v%VERSION% > "%OUTPUT_DIR%\.portable"
echo Built: %date% %time% >> "%OUTPUT_DIR%\.portable"
echo Platform: windows-%ARCH% >> "%OUTPUT_DIR%\.portable"

REM Create ZIP
echo [INFO] Creating ZIP archive...
cd /d "%BUILD_DIR%"
powershell -Command "Compress-Archive -Path '%OUTPUT_NAME%' -DestinationPath '%RELEASE_DIR%\%OUTPUT_NAME%.zip' -Force"

echo.
echo [SUCCESS] Build complete!
echo Package: %RELEASE_DIR%\%OUTPUT_NAME%.zip
echo.

dir "%RELEASE_DIR%"

endlocal

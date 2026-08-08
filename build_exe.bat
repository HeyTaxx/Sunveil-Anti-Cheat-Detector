@echo off
echo ================================================================
echo   Building Standalone Sunveil Overwatch Anti-Cheat Scanner .exe
echo ================================================================
echo.

cd /d "%~dp0"

dotnet publish scanner/CheatDetector/CheatDetector.csproj -c Release -r win-x64 -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true --self-contained true -o release/

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================================
    echo   BUILD SUCCESSFUL!
    echo   Output: release\CheatDetector.exe
    echo ================================================================
) else (
    echo.
    echo [ERROR] Build failed! Check errors above.
)
pause

@echo off
setlocal

set GRADLE_VERSION=9.6.0
set EXPECTED_SHA256=bbaeb2fef8710818cf0e261201dab964c572f92b942812df0c3620d62a529a01

if not defined GRADLE_USER_HOME set GRADLE_USER_HOME=%USERPROFILE%\.gradle
set DIST_ROOT=%GRADLE_USER_HOME%\wrapper\dists\jegpant-gradle-%GRADLE_VERSION%
set DIST_DIR=%DIST_ROOT%\gradle-%GRADLE_VERSION%
set ZIP_FILE=%DIST_ROOT%\gradle-%GRADLE_VERSION%-bin.zip
set DIST_URL=https://services.gradle.org/distributions/gradle-%GRADLE_VERSION%-bin.zip

if not exist "%DIST_DIR%\bin\gradle.bat" (
    if not exist "%DIST_ROOT%" mkdir "%DIST_ROOT%"
    if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"

    echo Downloading Gradle %GRADLE_VERSION%...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$ErrorActionPreference='Stop'; Invoke-WebRequest -Uri '%DIST_URL%' -OutFile '%ZIP_FILE%'; $actual=(Get-FileHash -Algorithm SHA256 '%ZIP_FILE%').Hash.ToLowerInvariant(); if ($actual -ne '%EXPECTED_SHA256%') { Remove-Item '%ZIP_FILE%' -Force; throw 'Gradle distribution SHA-256 mismatch' }; Expand-Archive -LiteralPath '%ZIP_FILE%' -DestinationPath '%DIST_ROOT%' -Force; Remove-Item '%ZIP_FILE%' -Force"
    if errorlevel 1 exit /b 1
)

call "%DIST_DIR%\bin\gradle.bat" %*
exit /b %ERRORLEVEL%

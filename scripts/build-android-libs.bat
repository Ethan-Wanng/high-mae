@echo off
setlocal

set "ROOT=%~dp0.."
set "OUTDIR=%ROOT%\flutter_ui\android\app\src\main\jniLibs"

echo Building Android libraries...
if "%ANDROID_NDK_HOME%"=="" (
    echo [ERROR] ANDROID_NDK_HOME environment variable is not set.
    echo Please set it to your Android NDK path (e.g. C:\Users\Username\AppData\Local\Android\Sdk\ndk\25.2.9519653)
    exit /b 1
)

:: Ensure outdir exists
mkdir "%OUTDIR%\arm64-v8a" 2>nul
mkdir "%OUTDIR%\armeabi-v7a" 2>nul
mkdir "%OUTDIR%\x86_64" 2>nul

echo Building arm64-v8a...
set GOOS=android
set GOARCH=arm64
set CGO_ENABLED=1
set CC=%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android30-clang.cmd
go build -buildmode=c-shared -o "%OUTDIR%\arm64-v8a\libwing.so" "%ROOT%\mobile"

echo Building armeabi-v7a...
set GOOS=android
set GOARCH=arm
set GOARM=7
set CGO_ENABLED=1
set CC=%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi30-clang.cmd
go build -buildmode=c-shared -o "%OUTDIR%\armeabi-v7a\libwing.so" "%ROOT%\mobile"

echo Building x86_64...
set GOOS=android
set GOARCH=amd64
set CGO_ENABLED=1
set CC=%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\x86_64-linux-android30-clang.cmd
go build -buildmode=c-shared -o "%OUTDIR%\x86_64\libwing.so" "%ROOT%\mobile"

echo Android libraries built successfully.
endlocal

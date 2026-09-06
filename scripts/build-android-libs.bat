@echo off
setlocal

set "ROOT=%~dp0.."
set "OUTDIR=%ROOT%\flutter_ui\android\app\src\main\jniLibs"

echo Building Android libraries...
:: arm64-v8a can use Go's internal Android linker.
mkdir "%OUTDIR%\arm64-v8a" 2>nul

echo Building arm64-v8a...
set GOOS=android
set GOARCH=arm64
set CGO_ENABLED=0
go build -o "%OUTDIR%\arm64-v8a\libwing_backend.so" "%ROOT%\mobile"
if errorlevel 1 exit /b 1

if "%ANDROID_NDK_HOME%"=="" (
    echo [WARN] ANDROID_NDK_HOME is not set; skipping armeabi-v7a and x86_64 backends.
    exit /b 0
)

mkdir "%OUTDIR%\armeabi-v7a" 2>nul
mkdir "%OUTDIR%\x86_64" 2>nul
set CGO_ENABLED=1

echo Building armeabi-v7a...
set GOOS=android
set GOARCH=arm
set GOARM=7
set CGO_ENABLED=1
set CC=%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\armv7a-linux-androideabi30-clang.cmd
go build -o "%OUTDIR%\armeabi-v7a\libwing_backend.so" "%ROOT%\mobile"
if errorlevel 1 exit /b 1

echo Building x86_64...
set GOOS=android
set GOARCH=amd64
set CGO_ENABLED=1
set CC=%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\x86_64-linux-android30-clang.cmd
go build -o "%OUTDIR%\x86_64\libwing_backend.so" "%ROOT%\mobile"
if errorlevel 1 exit /b 1

echo Android libraries built successfully.
endlocal

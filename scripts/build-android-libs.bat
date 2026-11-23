@echo off
setlocal

set "ROOT=%~dp0.."
set "OUTDIR=%ROOT%\flutter_ui\android\app\src\main\jniLibs"
set "TAGS=with_quic,with_utls,with_gvisor"

echo Building Android libraries...
mkdir "%OUTDIR%\arm64-v8a" 2>nul

if "%ANDROID_NDK_HOME%"=="" (
    echo [WARN] ANDROID_NDK_HOME is not set; building arm64-v8a with CGO_ENABLED=0 ^(runtime DNS fallback^) and skipping armeabi-v7a and x86_64.
    set GOOS=android
    set GOARCH=arm64
    set CGO_ENABLED=0
    go build -tags "%TAGS%" -o "%OUTDIR%\arm64-v8a\libwing_backend.so" "%ROOT%\mobile"
    if errorlevel 1 exit /b 1
    echo Android arm64-v8a library built with CGO_ENABLED=0.
    exit /b 0
)

set "LLVM_BIN=%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin"

mkdir "%OUTDIR%\armeabi-v7a" 2>nul
mkdir "%OUTDIR%\x86_64" 2>nul

call :find_clang "aarch64-linux-android" CLANG_ARM64
if "%CLANG_ARM64%"=="" (
    echo [ERROR] arm64-v8a NDK compiler not found in "%LLVM_BIN%".
    exit /b 1
)
echo Building arm64-v8a with %CLANG_ARM64%...
set GOOS=android
set GOARCH=arm64
set CGO_ENABLED=1
set "CC=%CLANG_ARM64%"
go build -tags "%TAGS%" -o "%OUTDIR%\arm64-v8a\libwing_backend.so" "%ROOT%\mobile"
if errorlevel 1 exit /b 1

call :find_clang "armv7a-linux-androideabi" CLANG_ARM
if "%CLANG_ARM%"=="" (
    echo [ERROR] armeabi-v7a NDK compiler not found in "%LLVM_BIN%".
    exit /b 1
)
echo Building armeabi-v7a with %CLANG_ARM%...
set GOOS=android
set GOARCH=arm
set GOARM=7
set CGO_ENABLED=1
set "CC=%CLANG_ARM%"
go build -tags "%TAGS%" -o "%OUTDIR%\armeabi-v7a\libwing_backend.so" "%ROOT%\mobile"
if errorlevel 1 exit /b 1

call :find_clang "x86_64-linux-android" CLANG_X86
if "%CLANG_X86%"=="" (
    echo [ERROR] x86_64 NDK compiler not found in "%LLVM_BIN%".
    exit /b 1
)
echo Building x86_64 with %CLANG_X86%...
set GOOS=android
set GOARCH=amd64
set CGO_ENABLED=1
set "CC=%CLANG_X86%"
go build -tags "%TAGS%" -o "%OUTDIR%\x86_64\libwing_backend.so" "%ROOT%\mobile"
if errorlevel 1 exit /b 1

echo Android libraries built successfully.
exit /b 0

:find_clang
set "%~2="
for %%A in (21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36) do (
    if exist "%LLVM_BIN%\%~1%%A-clang.cmd" (
        set "%~2=%LLVM_BIN%\%~1%%A-clang.cmd"
        goto :eof
    )
)
goto :eof

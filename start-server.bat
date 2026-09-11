@echo off
rem 拾光 · 校园失物招领 —— 一键启动（见面会演示用）
cd /d "%~dp0"

rem 找 Node：优先系统 PATH，找不到再用常见安装位置兜底
set "NODE_EXE=node"
where node >nul 2>nul
if %errorlevel% neq 0 (
  for %%P in ("D:\software\nodejs\node.exe" "C:\Program Files\nodejs\node.exe" "%LOCALAPPDATA%\Programs\nodejs\node.exe") do (
    if exist %%~P set "NODE_EXE=%%~P"
  )
)
if "%NODE_EXE%"=="node" (
  echo [ERROR] Node.js not found. Please install Node.js 18 or newer first.
  pause
  exit /b 1
)
if not "%NODE_EXE%"=="node" if not exist "%NODE_EXE%" (
  echo [ERROR] Node.js not found. Please install Node.js 18 or newer first.
  pause
  exit /b 1
)

echo ============================================
echo  拾光 · 校园失物招领  服务启动中...
echo  展示地址  http://localhost:3000
echo  管理员    admin / 123456
echo  普通用户  demo / li / zhao  密码均为 123456
echo  （关闭本窗口即停止服务）
echo ============================================

rem 自动打开演示页面
start "" http://localhost:3000/

%NODE_EXE% server.js
pause

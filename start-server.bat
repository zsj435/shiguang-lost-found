@echo off
rem Start the Shiguang Lost-and-Found backend (Supabase mode)
chcp 65001 >nul
cd /d "%~dp0"

set NODE_EXE=
where node >nul 2>nul && set NODE_EXE=node
if not defined NODE_EXE if exist "D:\software\nodejs\node.exe" set "NODE_EXE=D:\software\nodejs\node.exe"
if not defined NODE_EXE (
  echo [ERROR] Node.js not found. Please install Node.js 18 or newer first.
  pause
  exit /b 1
)
if not exist ".env" (
  echo [ERROR] .env not found. SUPABASE_URL / SUPABASE_SECRET_KEY required.
  pause
  exit /b 1
)

echo ============================================
echo  Shiguang Lost and Found server (Supabase)
echo  Admin   13800000001 / 123456
echo  Users   13800000002 / 13800000003 / 13800000004  password 123456
echo  URL     http://localhost:3000
echo ============================================
"%NODE_EXE%" --env-file=.env server.js
pause

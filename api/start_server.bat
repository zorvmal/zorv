@echo off
echo ============================================
echo   ZORV License Server v2.0.0
echo ============================================
echo.

REM Verificar Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERRO: Python nao encontrado!
    echo Instale em: https://python.org
    pause
    exit /b 1
)

echo [1/2] Instalando dependencias...
pip install -r requirements.txt
echo.

echo [2/2] Iniciando servidor...
echo.
echo Servidor rodando em: http://localhost:5000
echo Admin Panel: abra admin-panel/index.html
echo.
echo Pressione Ctrl+C para parar
echo.
python server.py
pause

#!/bin/bash
echo "============================================"
echo "  ZORV License Server v2.0.0"
echo "============================================"
echo ""

# Instalar dependências
pip3 install -r requirements.txt

echo ""
echo "Servidor rodando em: http://localhost:5000"
echo "Pressione Ctrl+C para parar"
echo ""

python3 server.py

#!/bin/bash

VENV_NAME="panhandlr_venv"
echo "[+] Welcome to Panhandlr Setup"

if [ -d "$VENV_NAME" ]; then
    echo "[*] Virtual environment '$VENV_NAME' already exists. Activating."
else
    echo "[*] Creating Python virtual environment: $VENV_NAME..."
    python3 -m venv "$VENV_NAME"
fi

source "$VENV_NAME/bin/activate"

pip install -q --upgrade pip
pip install -q -r requirements.txt


python3 panhandlr.py

deactivate
echo "[+] Panhandlr exited."

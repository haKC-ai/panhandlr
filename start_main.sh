#!/bin/bash

VENV_NAME="panhandlr_venv"
echo "[+] PANHANDLR building enviornment and charging laz0rz"

if [ -d "$VENV_NAME" ]; then
else
    python3 -m venv "$VENV_NAME"
fi

source "$VENV_NAME/bin/activate"

pip install -q --upgrade pip
pip install -q -r requirements.txt

python3 panhandlr.py

deactivate
echo "[+] Panhandler exited."
# XCOM LLM Server

This is a simple Python TCP server to handle chat queries for XCOM 2 using different LLM providers.

## Requirements

- Python 3.8+
- `requests` package

## Installation

```
pip install -r requirements.txt
```

## Usage
- Put llm_tcp_server.py inside the config folder of the LLM mod, where XComLLM.ini is.
- Make a simple run_server.bat file to run it by double clicking instead of the cmd in the same config folder, containing the following 3 lines:
```
@echo off
python3 llm_tcp_server.py
pause
```
- Always open run_server.bat before launching the game.

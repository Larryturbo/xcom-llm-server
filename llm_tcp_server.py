import socket
import threading
import subprocess
import configparser
import requests
import json
import os

# Globals
MODEL_NAME = ""
RESPONSE_LENGTH = 150
TIMEOUT = 120
HOST = '127.0.0.1'
PORT = 9000
CONTEXT_SIZE = 2048
max_prompt_chars = 8000
CONFIG_PATH = 'XComLLM.ini'
prologue = ""
old_context = ""
API_KEY = ""
API_ENDPOINT = ""
PROVIDER = ""

request_lock = threading.Lock()
request_in_progress = False

def load_config():
    global MODEL_NAME, RESPONSE_LENGTH, TIMEOUT, HOST, PORT
    global CONTEXT_SIZE, max_prompt_chars, prologue, old_context
    global API_KEY, API_ENDPOINT, PROVIDER

    config = configparser.ConfigParser()
    try:
        config.read(CONFIG_PATH)

        PROVIDER = config.get('LLM', 'provider', fallback='ollama')
        MODEL_NAME = config.get('LLM', 'model', fallback='magnum-twilight-12b-Q6_K-1741194656458:latest')
        API_KEY = config.get('LLM', 'apikey', fallback='')
        API_ENDPOINT = config.get('LLM', 'endpoint', fallback='')
        RESPONSE_LENGTH = config.getint('LLM', 'response_length', fallback=150)
        TIMEOUT = config.getint('LLM', 'timeout', fallback=120)
        HOST = config.get('LLM', 'host', fallback='127.0.0.1')
        PORT = config.getint('LLM', 'port', fallback=9000)
        CONTEXT_SIZE = config.getint('LLM', 'context_size', fallback=2048)
        prologue = config.get('LLM', 'prologue', fallback='')
        old_context = config.get('LLM', 'oldcontext', fallback='')

        max_prompt_chars = CONTEXT_SIZE * 4

    except (configparser.Error, IOError) as e:
        print(f"[Config] Warning: Failed to load config, using defaults. Error: {e}")

    return config

def save_old_context(_, new_context):
    config = configparser.ConfigParser()
    try:
        config.read(CONFIG_PATH)
        if 'LLM' not in config:
            config['LLM'] = {}
            
        new_context = new_context.replace('\ufffd', '-')
        config['LLM']['oldcontext'] = new_context
        with open(CONFIG_PATH, 'w') as configfile:
            config.write(configfile)
    except (IOError, configparser.Error) as e:
        print(f"[Config] Warning: Could not save old context. Error: {e}")

def query_ollama(prompt):
    try:
        result = subprocess.run(
            ['ollama', 'run', MODEL_NAME],
            input=prompt,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=True,
            timeout=TIMEOUT
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "Error querying Ollama: Request timed out."
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() if e.stderr else str(e)
        return f"Error querying Ollama: {err_msg}"

def query_openai_compatible(prompt, prologue):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": prologue},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": RESPONSE_LENGTH,
        "temperature": 0.7
    }
    try:
        response = requests.post(API_ENDPOINT, headers=headers, json=data, timeout=TIMEOUT)
        response.raise_for_status()
        raw_text = response.content.decode('utf-8', errors='replace')
        json_data = json.loads(raw_text)
        return json_data['choices'][0]['message']['content'].strip()
    except Exception as e:
        return f"Error querying OpenAI-compatible model: {e}"

def query_gemini(prompt, prologue):
    url = f"{API_ENDPOINT}?key={API_KEY}"
    headers = {"Content-Type": "application/json"}
    data = {
        "contents": [
            {"role": "user", "parts": [{"text": prologue}]},
            {"role": "user", "parts": [{"text": prompt}]}
        ],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": RESPONSE_LENGTH
        }
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=TIMEOUT)
        response.raise_for_status()
        candidates = response.json().get("candidates", [])
        if not candidates:
            return "Gemini returned no response."
        return candidates[0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        return f"Error querying Gemini: {e}"

def query_anthropic(prompt, prologue):
    headers = {
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }

    system_prompt = prologue if prologue else ""
    data = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "system": system_prompt,
        "max_tokens": RESPONSE_LENGTH,
        "temperature": 0.7
    }

    try:
        response = requests.post(API_ENDPOINT, headers=headers, json=data, timeout=TIMEOUT)
        response.raise_for_status()
        response_json = response.json()
        return response_json['content'][0]['text'].strip()
    except Exception as e:
        return f"Error querying Anthropic: {e}"

def query_model(prompt):
    provider = PROVIDER.lower()
    if provider == "ollama":
        return query_ollama(prompt)
    elif provider == "gemini":
        return query_gemini(prompt, prologue)
    elif provider in ["anthropic", "claude", "sonnet"]:
        return query_anthropic(prompt, prologue)
    else:
        return query_openai_compatible(prompt, prologue)

def handle_client(conn, addr):
    global request_in_progress, old_context

    print(f"[Server] Connected by {addr}")
    with conn:
        buffer = ""
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    print(f"[Server] Connection closed by {addr}")
                    break

                buffer += data.decode('utf-8', errors='replace')

                if "[ENDXLLM]" not in buffer:
                    continue

                # Check and set request-in-progress
                with request_lock:
                    if request_in_progress:
                        conn.sendall(b"XLLM Busy, try again later\n")
                        continue
                    request_in_progress = True
                
                message_from_xcom, buffer = buffer.split("[ENDXLLM]", 1)
                message_from_xcom = message_from_xcom.strip()
                print(f"[Server] Received from XCOM2: {message_from_xcom}")

                # Load fresh config every request
                config = load_config()

                # === Manual memory wipe command ===
                if message_from_xcom.startswith("memorywipe"):
                    old_context = ""
                    save_old_context(config, "")
                    response = "Chat history wiped."
                    print(f"[Server] Sending to XCOM2: {response}")
                    conn.sendall((response + "\n").encode('utf-8'))
                    continue

                # Calculate how much space is left for old_context
                prologue_len = len(prologue)
                message_len = len(message_from_xcom)
                available_for_context = max_prompt_chars - (prologue_len + message_len)

                # Trim old_context from the start if it's too long
                trimmed_old_context = old_context
                if available_for_context < len(old_context):
                    trimmed_old_context = old_context[-available_for_context:]

                # Compose final full prompt
                full_prompt = prologue + trimmed_old_context + message_from_xcom + "Respond briefly, dialogue only."

                response = query_model(full_prompt).replace('\n', ' ').replace('\r', '').replace('[TOOL_CALLS]', '').replace('</s>', '').replace('\ufffd', '-').strip()
                trimmed_response = "XLLM" + response[:RESPONSE_LENGTH] + "[ENDXLLM]"
                response_only = response[:RESPONSE_LENGTH].replace('\ufffd', '-')
                print(f"[Server] Sending to XCOM2: {trimmed_response.encode('ascii', errors='replace').decode()}")
                conn.sendall((trimmed_response + "\n").encode('utf-8', errors='replace'))

                tag = "[Campaign Progress]"
                index = message_from_xcom.find(tag)

                if index != -1:
                    user_input = message_from_xcom[index + len(tag):].strip()
                else:
                    user_input = message_from_xcom.strip()

                # Save new old_context
                updated_context = trimmed_old_context + " The Commander said:" + user_input + " You replied:" + response_only
                save_old_context(config, updated_context)

            except ConnectionResetError:
                print(f"[Server] Connection reset by {addr}")
                break
            except Exception as e:
                print(f"[Server] Error with {addr}: {e}")
                break
            finally:
                with request_lock:
                    request_in_progress = False

def run_server():
    print(f"[Server] Starting on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    load_config()
    run_server()
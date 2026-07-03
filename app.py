import json
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify

BASE_URL = "https://dev-gw.tracksafe365.com"

VERIFICATION_PATH = "/services/glsmanagement/api/devices/factory/verification/{serial}"

AUTHENTICATE_PATH = "/services/glsstream/api/truck/authenticate/v2"
INFO_PATH = "/services/glsstream/api/truck/info/v2"

SOFTWARE_DOWNLOAD_PATH = "/services/glsstream/api/software-release/download-url/agent/{version}"
SOFTWARE_VERSION = "1.0.0-beta"

SERIAL_NUMBER_FILE = "/sys/firmware/devicetree/base/serial-number"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, "agent_state.json")

DOWNLOAD_DIR = os.path.join(SCRIPT_DIR, "downloaded")
LOCAL_BINARY_PATH = os.path.join(DOWNLOAD_DIR, f"agent-{SOFTWARE_VERSION}")

TOKEN_REFRESH_BUFFER_SECONDS = 60
VERIFICATION_RETRY_SECONDS = 10

FLASK_HOST = "127.0.0.1"
FLASK_PORT = 8787
HTTP_TIMEOUT = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("tracsafe-agent")

app = Flask(__name__)

_token_lock = threading.Lock()

_state = {}

def read_serial_number() -> str:
    try:
        with open(SERIAL_NUMBER_FILE, "r") as f:
            serial = f.read().strip().strip("\x00")
        if not serial:
            raise ValueError("Serial number bo'sh qaytdi")
        log.info(f"Serial number o'qildi: {serial}")
        return serial
    except Exception as e:
        log.error(f"Serial number o'qishda xato: {e}")
        raise

def load_state() -> dict:
    global _state
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                _state = json.load(f)
                log.info(f"State fayl yuklandi: {STATE_FILE}")
        except Exception as e:
            log.error(f"State faylni o'qishda xato, bo'shdan boshlaymiz: {e}")
            _state = {}
    else:
        log.info(f"State fayl topilmadi, yangi fayl yaratilmoqda: {STATE_FILE}")
        _state = {}
        save_state()
    return _state

def save_state():
    state_dir = os.path.dirname(STATE_FILE)
    if state_dir:
        os.makedirs(state_dir, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(_state, f, indent=2)
    log.info("State fayl saqlandi")

def verify_serial_number(serial: str):
    """
    Verification API'ga GET so'rov.
    200 qaytmaguncha har 10 sikundda qayta urinadi (tarmoq/server xatolarida ham).
    """
    url = BASE_URL + VERIFICATION_PATH.format(serial=serial)
    attempt = 1
    while True:
        try:
            log.info(f"Verification so'rovi yuborilmoqda (urinish #{attempt}): {url}")
            resp = requests.get(url, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                log.info("Verification muvaffaqiyatli o'tdi (200 OK)")
                return resp.json() if resp.content else None
            else:
                log.warning(
                    f"Verification hali 200 qaytarmadi. Status: {resp.status_code}, "
                    f"Body: {resp.text}. {VERIFICATION_RETRY_SECONDS} sikunddan keyin qayta urinadi."
                )
        except Exception as e:
            log.warning(
                f"Verification so'rovida xato: {e}. "
                f"{VERIFICATION_RETRY_SECONDS} sikunddan keyin qayta urinadi."
            )
        attempt += 1
        time.sleep(VERIFICATION_RETRY_SECONDS)

def authenticate(serial: str) -> dict:
    url = BASE_URL + AUTHENTICATE_PATH
    log.info(f"Authenticate so'rovi yuborilmoqda: {url}")
    resp = requests.post(
        url, json={"serialNumber": serial}, timeout=HTTP_TIMEOUT
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Authenticate muvaffaqiyatsiz. Status: {resp.status_code}, Body: {resp.text}"
        )
    data = resp.json()
    if "id_token" not in data or "expires_at" not in data:
        raise RuntimeError(f"Authenticate javobida id_token/expires_at yo'q: {data}")
    log.info(f"Yangi token olindi, expire: {data['expires_at']}")
    return data

def parse_iso_datetime(s: str) -> datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    match = re.match(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2})?$', s
    )
    if not match:
        return datetime.fromisoformat(s)

    base, frac, tz = match.groups()

    if frac:
        digits = frac[1:]
        digits = (digits + "000000")[:6]
        frac = "." + digits
    else:
        frac = ""

    if not tz:
        tz = "+00:00"

    normalized = f"{base}{frac}{tz}"
    return datetime.fromisoformat(normalized)

def is_token_expired(expires_at_str: str) -> bool:
    expires_at = parse_iso_datetime(expires_at_str)
    now = datetime.now(timezone.utc)
    remaining = (expires_at - now).total_seconds()
    return remaining <= TOKEN_REFRESH_BUFFER_SECONDS

def ensure_valid_token() -> str:
    with _token_lock:
        token = _state.get("id_token")
        expires_at = _state.get("expires_at")

        if token and expires_at and not is_token_expired(expires_at):
            return token

        log.info("Token yo'q yoki muddati tugagan, yangilanmoqda...")
        serial = _state["serial_number"]
        auth_data = authenticate(serial)

        _state["id_token"] = auth_data["id_token"]
        _state["expires_at"] = auth_data["expires_at"]
        save_state()

        return _state["id_token"]

def bootstrap():
    load_state()

    if _state.get("verified"):
        log.info(
            f"Bu qurilma allaqachon verified (serial: {_state.get('serial_number')}). "
            f"Verification qayta qilinmaydi."
        )
        ensure_valid_token()
        return

    log.info("Birinchi run aniqlandi - to'liq bootstrap boshlanmoqda")
    serial = read_serial_number()
    verify_serial_number(serial)

    auth_data = authenticate(serial)

    _state.update({
        "serial_number": serial,
        "verified": True,
        "id_token": auth_data["id_token"],
        "expires_at": auth_data["expires_at"],
    })
    save_state()
    log.info("Bootstrap tugadi. Qurilma endi doimiy verified holatda.")

def get_download_url(version: str) -> str:
    token = ensure_valid_token()
    url = BASE_URL + SOFTWARE_DOWNLOAD_PATH.format(version=version)
    log.info(f"Software-release download URL so'ralmoqda: {url}")
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Download-url so'rovi muvaffaqiyatsiz. Status: {resp.status_code}, Body: {resp.text}"
        )

    data = resp.json()
    download_url = data.get("url")
    if not download_url:
        raise RuntimeError(f"Javobda 'url' key topilmadi: {data}")

    log.info(f"Download URL olindi: {download_url}")
    return download_url

def download_binary(download_url: str, dest_path: str):
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    log.info(f"Fayl yuklab olinmoqda: {download_url}")
    with requests.get(download_url, stream=True, timeout=60) as resp:
        if resp.status_code != 200:
            raise RuntimeError(f"Fayl yuklab olishda xato. Status: {resp.status_code}")
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    os.chmod(dest_path, 0o755)
    log.info(f"Fayl yuklab olindi va executable qilindi: {dest_path}")

def launch_agent_binary():
    try:
        if os.path.exists(LOCAL_BINARY_PATH):
            log.info(f"Boshqaruvchi agent allaqachon yuklab olingan, qayta yuklanmaydi: {LOCAL_BINARY_PATH}")
        else:
            download_url = get_download_url(SOFTWARE_VERSION)
            download_binary(download_url, LOCAL_BINARY_PATH)
    except Exception as e:
        log.error(
            f"Boshqaruvchi agentni yuklab olishda xato: {e}. "
            f"Binary ishga tushirilmaydi, lekin Flask server ishlashda davom etadi."
        )
        return

    log.info(f"Boshqaruvchi agent ishga tushirilmoqda: {LOCAL_BINARY_PATH}")
    try:
        proc = subprocess.Popen([LOCAL_BINARY_PATH])
        log.info(f"Boshqaruvchi agent ishga tushdi (PID: {proc.pid}). Terminal buyruqlarni kutmoqda.")
        exit_code = proc.wait()
        if exit_code == 0:
            log.info(f"Boshqaruvchi agent normal tugadi. Exit code: {exit_code}")
        else:
            log.warning(f"Boshqaruvchi agent xato bilan tugadi. Exit code: {exit_code}")
    except Exception as e:
        log.error(f"Boshqaruvchi agentni ishga tushirishda xato: {e}")

@app.route("/token", methods=["GET"])
def get_token():
    try:
        token = ensure_valid_token()
        return jsonify({
            "token": token,
            "expires_at": _state.get("expires_at"),
        })
    except Exception as e:
        log.error(f"/token xatosi: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/info", methods=["GET"])
def get_info():
    try:
        token = ensure_valid_token()
        url = BASE_URL + INFO_PATH
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            return jsonify({
                "error": "info so'rovi muvaffaqiyatsiz",
                "status": resp.status_code,
                "body": resp.text,
            }), resp.status_code

        return jsonify(resp.json())
    except Exception as e:
        log.error(f"/info xatosi: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "verified": _state.get("verified", False),
        "serial_number": _state.get("serial_number"),
    })

if __name__ == "__main__":
    bootstrap()

    flask_thread = threading.Thread(
        target=lambda: app.run(host=FLASK_HOST, port=FLASK_PORT, use_reloader=False),
        daemon=True,
    )
    flask_thread.start()
    log.info(f"Flask server background'da ishga tushdi: http://{FLASK_HOST}:{FLASK_PORT}")

    launch_agent_binary()
    log.info("Boshqaruvchi agent jarayoni tugadi. Flask server hali ham ishlamoqda...")
    flask_thread.join()

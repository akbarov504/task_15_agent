import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify

BASE_URL = "https://dev-gw.tracksafe365.com"

VERIFICATION_PATH = "/services/glsmanagement/api/devices/factory/verification/{serial}"

AUTHENTICATE_PATH = "/services/glsstream/api/truck/authenticate/v2"
INFO_PATH = "/services/glsstream/api/truck/info/v2"

SERIAL_NUMBER_FILE = "/sys/firmware/devicetree/base/serial-number"

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_state.json")

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
    log.info(f"Flask server ishga tushmoqda: http://{FLASK_HOST}:{FLASK_PORT}")
    app.run(host=FLASK_HOST, port=FLASK_PORT)

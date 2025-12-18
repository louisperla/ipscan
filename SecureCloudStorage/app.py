import os, json, hashlib
from datetime import datetime
from io import BytesIO
from flask import Flask, request, render_template, send_file, redirect, url_for
from werkzeug.utils import secure_filename

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


APP_ROOT = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(APP_ROOT, "storage")
KEY_DIR = os.path.join(APP_ROOT, "keys")
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")

app = Flask(__name__)


def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def list_files():
    # We store encrypted files as *.bin with a *.json sidecar
    items = []
    for name in os.listdir(STORAGE_DIR):
        if not name.endswith(".bin"):
            continue
        meta_path = os.path.join(STORAGE_DIR, name + ".json")
        if not os.path.exists(meta_path):
            continue

        stat = os.stat(os.path.join(STORAGE_DIR, name))
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        items.append({
            "id": name,  # stored encrypted filename
            "name": meta.get("original_name", name),
            "size": f"{stat.st_size/1024:.1f} KB" if stat.st_size < 1024*1024 else f"{stat.st_size/1024/1024:.1f} MB",
            "date": datetime.fromtimestamp(stat.st_mtime).strftime("%m/%d/%Y"),
        })

    # newest first
    items.sort(key=lambda x: x["date"], reverse=True)
    return items


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "file" not in request.files:
            return redirect(url_for("index"))

        file = request.files["file"]
        if not file.filename:
            return redirect(url_for("index"))

        original_name = secure_filename(file.filename)
        file_bytes = file.read()

        # 1) Generate AES key + nonce
        aes_key = os.urandom(32)  # AES-256
        nonce = os.urandom(12)    # recommended size for AESGCM

        # 2) Encrypt file with AESGCM
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, file_bytes, None)  # includes auth tag internally

        # 3) Wrap AES key with RSA public key
        public_key = load_public_key()
        wrapped_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 4) Integrity hash of ciphertext
        cipher_hash = sha256_hex(ciphertext)

        # 5) Save encrypted file + metadata
        stored_name = f"{hashlib.sha256((original_name+str(os.urandom(6))).encode()).hexdigest()[:20]}.bin"
        enc_path = os.path.join(STORAGE_DIR, stored_name)
        meta_path = os.path.join(STORAGE_DIR, stored_name + ".json")

        with open(enc_path, "wb") as f:
            f.write(ciphertext)

        meta = {
            "original_name": original_name,
            "nonce_hex": nonce.hex(),
            "wrapped_key_hex": wrapped_key.hex(),
            "cipher_sha256": cipher_hash,
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return redirect(url_for("index"))

    files = list_files()
    return render_template("index.html", files=files)


@app.route("/download/<file_id>")
def download(file_id):
    # file_id is the stored encrypted filename (e.g., abc.bin)
    enc_path = os.path.join(STORAGE_DIR, file_id)
    meta_path = os.path.join(STORAGE_DIR, file_id + ".json")

    if not os.path.exists(enc_path) or not os.path.exists(meta_path):
        return "File not found", 404

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    with open(enc_path, "rb") as f:
        ciphertext = f.read()

    # verify hash before decrypt
    if sha256_hex(ciphertext) != meta.get("cipher_sha256"):
        return "Integrity check failed (SHA-256 mismatch).", 400

    nonce = bytes.fromhex(meta["nonce_hex"])
    wrapped_key = bytes.fromhex(meta["wrapped_key_hex"])

    private_key = load_private_key()
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    original_name = meta.get("original_name", "downloaded_file")
    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=original_name,
        mimetype="application/octet-stream"
    )


if __name__ == "__main__":
    app.run(debug=True)

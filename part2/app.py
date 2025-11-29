from flask import Flask, render_template, request, send_file
import os
import random
import json
from io import BytesIO

app = Flask(__name__)


# ------------------------------
# XOR (Вернам)
# ------------------------------
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])


# ------------------------------
# Генерация ключа
# ------------------------------
def generate_key(length: int) -> bytes:
    return os.urandom(length)


# ------------------------------
# Преобразование ключа в равнозначный
# ------------------------------
def transform_key(original: bytes) -> dict:
    length = len(original)
    perm = list(range(length))
    random.shuffle(perm)
    mask = os.urandom(length)
    shuffled = bytes(original[i] for i in perm)
    transformed = xor_bytes(shuffled, mask)
    return {"key": transformed.hex(), "perm": perm, "mask": mask.hex()}


def restore_key(entry: dict) -> bytes:
    key = bytes.fromhex(entry["key"])
    mask = bytes.fromhex(entry["mask"])
    perm = entry["perm"]
    unmasked = xor_bytes(key, mask)
    original = bytearray(len(perm))
    for i, p in enumerate(perm):
        original[p] = unmasked[i]
    return bytes(original)


# ------------------------------
# Создание группы равнозначных ключей
# ------------------------------
def create_key_group(key: bytes, count=10):
    return [transform_key(key) for _ in range(count)]


def encrypt(message: str, key: bytes) -> str:
    msg = message.encode("utf-8")
    return xor_bytes(msg, key).hex().upper()


def decrypt(cipher_hex: str, key: bytes) -> str:
    cipher = bytes.fromhex(cipher_hex)
    return xor_bytes(cipher, key).decode("utf-8")


# ------------------------------
# Routes
# ------------------------------
key_groups_memory = {}  # словарь для хранения группы ключей в памяти по id


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    group_id = None

    if request.method == "POST":
        msg = request.form.get("message", "")
        msg_bytes = msg.encode("utf-8")

        # Генерация исходного ключа и группы
        base_key = generate_key(len(msg_bytes))
        group = create_key_group(base_key)

        # сохраняем группу в памяти с уникальным id
        group_id = str(random.randint(1000, 9999))
        key_groups_memory[group_id] = group

        # Выбор ключа: пользовательский индекс или случайный
        idx_str = request.form.get("key_index")
        if idx_str and idx_str.isdigit() and 0 <= int(idx_str) < len(group):
            entry = group[int(idx_str)]
        else:
            entry = random.choice(group)

        use_key = restore_key(entry)
        cipher = encrypt(msg, use_key)
        decoded = decrypt(cipher, use_key)

        result = {
            "message": msg,
            "cipher": cipher,
            "decoded": decoded,
            "key": use_key.hex(),
            "group_size": len(group),
            "group_id": group_id
        }

    return render_template("index.html", result=result)


@app.route("/download/<group_id>")
def download_group(group_id):
    group = key_groups_memory.get(group_id)
    if not group:
        return "Группа ключей не найдена", 404

    # создаём файл в памяти
    buffer = BytesIO()
    buffer.write(json.dumps(group, indent=2).encode("utf-8"))
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="key_group.json", mimetype="application/json")


if __name__ == "__main__":
    app.run(debug=True)

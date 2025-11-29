import os

from flask import Flask, render_template, request

app = Flask(__name__)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("Длины операндов должны совпадать.")
    return bytes(a ^ b for a, b in zip(left, right))


def normalize_hex(value: str) -> str:
    return "".join(value.split()).lower()


def hex_to_bytes(value: str, field: str) -> bytes:
    cleaned = normalize_hex(value)
    if not cleaned:
        raise ValueError(f"Поле «{field}» не должно быть пустым.")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"Поле «{field}» должно содержать чётное число hex-символов.")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"Поле «{field}» содержит недопустимые hex-символы.") from exc


def bytes_to_hex(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


@app.route("/", methods=["GET", "POST"])
def index():
    form_values = {
        "gen_plaintext": "",
        "enc_plaintext": "",
        "enc_key_hex": "",
        "key_plaintext": "",
        "key_cipher_hex": "",
        "decipher_key_hex": "",
        "decipher_cipher_hex": "",
    }
    context = {
        "errors": [],
        "generated_key_hex": None,
        "encryption_result": None,
        "key_result": None,
        "decipher_result": None,
        "form_values": form_values,
    }

    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "encrypt":
                plaintext = request.form.get("enc_plaintext", "")
                key_hex = request.form.get("enc_key_hex", "")
                form_values["enc_plaintext"] = plaintext
                form_values["enc_key_hex"] = key_hex

                plain_bytes = plaintext.encode("utf-8")
                key_bytes = hex_to_bytes(key_hex, "Ключ")
                if len(plain_bytes) != len(key_bytes):
                    raise ValueError(
                        "Длины открытого текста и ключа должны совпадать (в байтах)."
                    )

                cipher_bytes = xor_bytes(plain_bytes, key_bytes)
                context["encryption_result"] = {
                    "cipher_hex": bytes_to_hex(cipher_bytes),
                    "key_hex": bytes_to_hex(key_bytes),
                    "length": len(plain_bytes),
                    "decoded": xor_bytes(cipher_bytes, key_bytes).decode("utf-8"),
                }
                form_values["key_cipher_hex"] = context["encryption_result"]["cipher_hex"]
                form_values["decipher_cipher_hex"] = context["encryption_result"]["cipher_hex"]
            elif action == "generate_key":
                source_text = request.form.get("gen_plaintext", "")
                form_values["gen_plaintext"] = source_text
                if not source_text:
                    raise ValueError("Введите текст для генерации ключа.")
                source_bytes = source_text.encode("utf-8")
                key_bytes = os.urandom(len(source_bytes))
                key_hex = bytes_to_hex(key_bytes)
                form_values["enc_key_hex"] = key_hex
                context["generated_key_hex"] = key_hex
            elif action == "derive_key":
                plaintext = request.form.get("key_plaintext", "")
                cipher_hex = request.form.get("key_cipher_hex", "")
                form_values["key_plaintext"] = plaintext
                form_values["key_cipher_hex"] = cipher_hex

                plain_bytes = plaintext.encode("utf-8")
                cipher_bytes = hex_to_bytes(cipher_hex, "Шифртекст")
                if len(plain_bytes) != len(cipher_bytes):
                    raise ValueError(
                        "Длины шифртекста и открытого текста должны совпадать."
                    )

                key_bytes = xor_bytes(cipher_bytes, plain_bytes)
                context["key_result"] = {
                    "key_hex": bytes_to_hex(key_bytes),
                    "decoded": xor_bytes(cipher_bytes, key_bytes).decode("utf-8"),
                }
                form_values["decipher_key_hex"] = context["key_result"]["key_hex"]
                form_values["decipher_cipher_hex"] = form_values["key_cipher_hex"]
            elif action == "decrypt":
                key_hex = request.form.get("decipher_key_hex", "")
                cipher_hex = request.form.get("decipher_cipher_hex", "")
                form_values["decipher_key_hex"] = key_hex
                form_values["decipher_cipher_hex"] = cipher_hex

                key_bytes = hex_to_bytes(key_hex, "Ключ")
                cipher_bytes = hex_to_bytes(cipher_hex, "Шифртекст")
                if len(key_bytes) != len(cipher_bytes):
                    raise ValueError("Ключ и шифртекст должны быть одинаковой длины.")

                plain_bytes = xor_bytes(cipher_bytes, key_bytes)
                context["decipher_result"] = {
                    "plaintext": plain_bytes.decode("utf-8", errors="replace"),
                }
            else:
                context["errors"].append("Неизвестное действие.")
        except ValueError as error:
            context["errors"].append(str(error))

    return render_template("index.html", **context)


if __name__ == "__main__":
    app.run(debug=True)

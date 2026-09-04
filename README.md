# wg-emu-client

Учебный VPN-клиент на Python, эмулирующий базовые криптографические принципы
WireGuard: **X25519 ECDH** для выработки общего секрета и **ChaCha20-Poly1305**
для шифрования UDP-пакетов.

## ⚠️ Важно

Это **не** реализация протокола WireGuard и **не совместимо** с реальным
`wireguard`/`wg-quick`. Настоящий WireGuard использует протокол
`Noise_IKpsk2` со строгой схемой handshake, cookie-защитой от DoS и
счётчиками пакетов для защиты от replay-атак. Этот проект — упрощённая
эмуляция для обучения (ECDH, AEAD-шифрование, работа с UDP), не для
продакшн-использования. Для реального VPN используйте официальный
[WireGuard](https://www.wireguard.com/).

## Возможности

- Конфигурация в формате `config.json` или классическом `wg0.conf` (ini)
- X25519 ECDH + HKDF-SHA256 + опциональный PresharedKey
- ChaCha20-Poly1305 со случайным nonce на каждый пакет
- Приём/отправка по UDP в отдельных потоках, keepalive
- Graceful shutdown по `SIGINT`/`SIGTERM`
- Горячая перезагрузка конфигурации: `client.reload_config()`
- Заглушка TUN-интерфейса с инструкциями по маршрутизации (Linux/macOS/Windows)

## Установка

```bash
pip install -r requirements.txt
```

## Использование

Скопируйте пример конфигурации и подставьте свои ключи:

```bash
cp examples/config.example.json config.json
# или
cp examples/wg0.example.conf wg0.conf
```

Запуск:

```bash
python wg_emu_client.py --config config.json
python wg_emu_client.py --config wg0.conf -v   # подробные логи
```

Остановка: `Ctrl+C`.

## Генерация ключей X25519 (пример на Python)

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import base64

priv = X25519PrivateKey.generate()
pub = priv.public_key()

print("PrivateKey:", base64.b64encode(priv.private_bytes_raw()).decode())
print("PublicKey :", base64.b64encode(pub.public_bytes_raw()).decode())
```

## Структура проекта

```
wg-emu-client/
├── wg_emu_client.py          # основной клиент
├── examples/
│   ├── config.example.json
│   └── wg0.example.conf
├── requirements.txt
├── LICENSE
└── README.md
```

## Лицензия

MIT — см. [LICENSE](LICENSE).

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wg_emu_client.py — учебный VPN-клиент, эмулирующий базовые принципы WireGuard.

ВАЖНО (честно и прямо):
Это НЕ реализация настоящего протокола WireGuard и НЕ совместимо с реальным
сервером wireguard-tools / wg-quick. Настоящий WireGuard использует протокол
Noise_IKpsk2 с конкретной последовательностью handshake-сообщений (initiation/
response), cookie-механизмом защиты от DoS, счётчиками nonce по протоколу и
т.д. Здесь реализована упрощённая, учебная схема:

    X25519 ECDH  ->  HKDF-подобное производство ключа  ->  ChaCha20-Poly1305

Она годится для изучения принципов (ECDH, AEAD-шифрование пакетов, работа с
UDP, конфигурацией в стиле wg-conf), но НЕ годится для продакшена и не
заменяет проверенные реализации (WireGuard, OpenVPN, IPsec).

Зависимости:
    pip install cryptography pycryptodome
    (опционально, для настоящего TUN-интерфейса на Linux)
    pip install pyroute2 python-pytun

Пример конфигурационного файла config.json:
{
    "PrivateKey": "SGVsbG8gd29ybGQgLSDvv73RgtC+INC90LUg0LrQu9GO0YchIQ==",
    "Address": "10.0.0.2/24",
    "Peer": {
        "PublicKey": "b3RoZXJfcGVlcl9wdWJsaWNfa2V5X2Jhc2U2NF9oZXJl==",
        "Endpoint": "vpn.example.com:51820",
        "AllowedIPs": ["0.0.0.0/0"],
        "PresharedKey": null
    }
}

Пример конфигурационного файла wg0.conf (классический ini-подобный формат):
[Interface]
PrivateKey = SGVsbG8gd29ybGQgLSDvv73RgtC+INC90LUg0LrQu9GO0YchIQ==
Address = 10.0.0.2/24

[Peer]
PublicKey = b3RoZXJfcGVlcl9wdWJsaWNfa2V5X2Jhc2U2NF9oZXJl==
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
# PresharedKey = ...

Запуск:
    python wg_emu_client.py --config config.json
    python wg_emu_client.py --config wg0.conf
"""

import argparse
import base64
import configparser
import json
import logging
import os
import secrets
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    print("Требуется пакет 'cryptography': pip install cryptography", file=sys.stderr)
    raise

try:
    from Crypto.Cipher import ChaCha20_Poly1305
except ImportError:
    print("Требуется пакет 'pycryptodome': pip install pycryptodome", file=sys.stderr)
    raise


# --------------------------------------------------------------------------
# Логирование
# --------------------------------------------------------------------------

def setup_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("wg_emu")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger


log = setup_logging()


# --------------------------------------------------------------------------
# Модель конфигурации
# --------------------------------------------------------------------------

@dataclass
class PeerConfig:
    public_key_b64: str
    endpoint_host: str
    endpoint_port: int = 51820
    allowed_ips: List[str] = field(default_factory=lambda: ["0.0.0.0/0"])
    preshared_key_b64: Optional[str] = None

    @property
    def endpoint(self) -> Tuple[str, int]:
        return (self.endpoint_host, self.endpoint_port)


@dataclass
class ClientConfig:
    private_key_b64: str
    address: str
    peer: PeerConfig

    @staticmethod
    def _split_endpoint(raw: str) -> Tuple[str, int]:
        raw = raw.strip()
        if ":" in raw:
            host, port_s = raw.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                host, port = raw, 51820
        else:
            host, port = raw, 51820
        return host, port

    @classmethod
    def from_json(cls, path: Path) -> "ClientConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        peer_data = data["Peer"]
        host, port = cls._split_endpoint(peer_data["Endpoint"])
        peer = PeerConfig(
            public_key_b64=peer_data["PublicKey"],
            endpoint_host=host,
            endpoint_port=port,
            allowed_ips=peer_data.get("AllowedIPs", ["0.0.0.0/0"]),
            preshared_key_b64=peer_data.get("PresharedKey"),
        )
        return cls(
            private_key_b64=data["PrivateKey"],
            address=data["Address"],
            peer=peer,
        )

    @classmethod
    def from_ini(cls, path: Path) -> "ClientConfig":
        parser = configparser.ConfigParser(strict=False)
        # wg-conf формат допускает дублирующиеся ключи и специфичный регистр,
        # поэтому читаем максимально терпимо.
        parser.read(path, encoding="utf-8")
        iface = parser["Interface"]
        peer_section = parser["Peer"]

        host, port = cls._split_endpoint(peer_section.get("Endpoint", ""))
        allowed_ips_raw = peer_section.get("AllowedIPs", "0.0.0.0/0")
        allowed_ips = [ip.strip() for ip in allowed_ips_raw.split(",") if ip.strip()]

        peer = PeerConfig(
            public_key_b64=peer_section.get("PublicKey"),
            endpoint_host=host,
            endpoint_port=port,
            allowed_ips=allowed_ips,
            preshared_key_b64=peer_section.get("PresharedKey", fallback=None),
        )
        return cls(
            private_key_b64=iface.get("PrivateKey"),
            address=iface.get("Address"),
            peer=peer,
        )

    @classmethod
    def load(cls, path: Path) -> "ClientConfig":
        if path.suffix.lower() == ".json":
            return cls.from_json(path)
        else:
            # По умолчанию считаем ini-формат (wg0.conf и подобные)
            return cls.from_ini(path)


# --------------------------------------------------------------------------
# Криптографический движок: X25519 ECDH + ChaCha20-Poly1305
# --------------------------------------------------------------------------

class CryptoEngine:
    """
    Инкапсулирует вычисление общего ключа сессии и AEAD-шифрование/
    расшифровку пакетов.

    Схема выработки ключа:
        shared_secret = X25519(my_private, peer_public)
        session_key   = HKDF-SHA256(shared_secret, salt=PSK или b'', info=b"wg-emu-session")

    Если задан PresharedKey — он подмешивается как HKDF-salt (что усиливает
    защиту от компрометации ECDH, аналогично идее WireGuard, но без полного
    протокола Noise).
    """

    NONCE_LEN = 12  # ChaCha20-Poly1305 требует 12-байтовый nonce

    def __init__(self, private_key_b64: str, peer_public_key_b64: str,
                 preshared_key_b64: Optional[str] = None):
        try:
            priv_bytes = base64.b64decode(private_key_b64)
            pub_bytes = base64.b64decode(peer_public_key_b64)
            if len(priv_bytes) != 32 or len(pub_bytes) != 32:
                raise ValueError("Ключ X25519 должен быть длиной 32 байта")
        except Exception as e:
            raise ValueError(f"Некорректный формат ключа (base64/длина): {e}")

        self._private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
        self._peer_public_key = X25519PublicKey.from_public_bytes(pub_bytes)

        self.public_key_b64 = base64.b64encode(
            self._private_key.public_key().public_bytes_raw()
        ).decode("ascii")

        psk_bytes = b""
        if preshared_key_b64:
            try:
                psk_bytes = base64.b64decode(preshared_key_b64)
            except Exception as e:
                raise ValueError(f"Некорректный PresharedKey: {e}")

        self.session_key = self._derive_session_key(psk_bytes)

    def _derive_session_key(self, psk_bytes: bytes) -> bytes:
        """ECDH + HKDF -> 32-байтовый ключ для ChaCha20-Poly1305."""
        shared_secret = self._private_key.exchange(self._peer_public_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=psk_bytes if psk_bytes else None,
            info=b"wg-emu-session-v1",
        )
        return hkdf.derive(shared_secret)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Возвращает nonce(12) || ciphertext || tag(16)."""
        nonce = secrets.token_bytes(self.NONCE_LEN)
        cipher = ChaCha20_Poly1305.new(key=self.session_key, nonce=nonce)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ciphertext + tag

    def decrypt(self, packet: bytes, aad: bytes = b"") -> bytes:
        if len(packet) < self.NONCE_LEN + 16:
            raise ValueError("Пакет слишком короткий для валидного AEAD-конверта")
        nonce = packet[:self.NONCE_LEN]
        tag = packet[-16:]
        ciphertext = packet[self.NONCE_LEN:-16]
        cipher = ChaCha20_Poly1305.new(key=self.session_key, nonce=nonce)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)


# --------------------------------------------------------------------------
# Заглушка для TUN-интерфейса и маршрутизации
# --------------------------------------------------------------------------

class TunStub:
    """
    Заглушка сетевого TUN-интерфейса.

    Полноценная реализация требует прав администратора/root и платформенно-
    зависимого кода:
      - Linux: /dev/net/tun + pyroute2 (или python-pytun)
      - macOS: /dev/utunN (нет универсального python-пакета, часто нужен
        свой ioctl-код или сторонние утилиты)
      - Windows: драйвер Wintun + wintun.dll через ctypes, либо WireGuard NT

    Здесь мы просто логируем, что "было бы отправлено/получено" в туннель,
    и объясняем, что нужно сделать вручную для реальной маршрутизации.
    """

    def __init__(self, address: str, allowed_ips: List[str], logger: logging.Logger):
        self.address = address
        self.allowed_ips = allowed_ips
        self.log = logger
        self._opened = False

    def open(self):
        self._opened = True
        self.log.warning(
            "TUN-интерфейс НЕ создан (это заглушка). "
            "Реальный туннель требует root/admin прав и платформенного кода."
        )
        self._print_routing_instructions()

    def _print_routing_instructions(self):
        self.log.info("---- Инструкции по ручной настройке маршрутизации ----")
        self.log.info(f"Адрес клиента для интерфейса: {self.address}")
        self.log.info(f"Разрешённые сети (AllowedIPs): {', '.join(self.allowed_ips)}")
        self.log.info("Linux (пример, интерфейс wg0 уже создан вручную):")
        self.log.info("  sudo ip link add dev wg0 type wireguard   # либо через wireguard-tools")
        self.log.info(f"  sudo ip addr add {self.address} dev wg0")
        self.log.info("  sudo ip link set up dev wg0")
        for net in self.allowed_ips:
            self.log.info(f"  sudo ip route add {net} dev wg0")
        self.log.info("macOS (аналогично, интерфейс utunN):")
        self.log.info(f"  sudo ifconfig utun9 {self.address.split('/')[0]} {self.address.split('/')[0]} up")
        for net in self.allowed_ips:
            self.log.info(f"  sudo route add -net {net} -interface utun9")
        self.log.info("Windows (PowerShell, интерфейс WireGuard/Wintun):")
        self.log.info(f"  netsh interface ip set address name=\"WG\" static {self.address.split('/')[0]} 255.255.255.0")
        for net in self.allowed_ips:
            self.log.info(f"  route add {net.split('/')[0]} mask 255.255.255.0 0.0.0.0 if <IFACE_INDEX>")
        self.log.info("Также можно автоматизировать через pyroute2 (Linux) — см. класс TunStub.setup_with_pyroute2.")
        self.log.info("--------------------------------------------------------")

    def setup_with_pyroute2(self):
        """
        Пример (не выполняется автоматически) настройки через pyroute2 на Linux.
        Требует root и установленного пакета pyroute2.
        """
        try:
            from pyroute2 import IPRoute  # noqa: F401
        except ImportError:
            self.log.error("pyroute2 не установлен: pip install pyroute2")
            return
        self.log.info(
            "Здесь могла бы быть автоматическая настройка интерфейса и "
            "маршрутов через pyroute2.IPRoute(). Оставлено как заглушка, "
            "так как создание wireguard-интерфейса требует поддержки ядра "
            "и root-прав."
        )

    def close(self):
        if self._opened:
            self.log.info("TUN-интерфейс (заглушка) закрыт")
        self._opened = False


# --------------------------------------------------------------------------
# Основной VPN-клиент
# --------------------------------------------------------------------------

class VPNClient:
    def __init__(self, config_path: Path, logger: Optional[logging.Logger] = None):
        self.config_path = config_path
        self.log = logger or log
        self.config: ClientConfig = ClientConfig.load(config_path)
        self.crypto: CryptoEngine = self._build_crypto(self.config)

        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._reload_lock = threading.RLock()

        self._recv_thread: Optional[threading.Thread] = None
        self._send_thread: Optional[threading.Thread] = None

        self.tun = TunStub(self.config.address, self.config.peer.allowed_ips, self.log)

        self.socket_timeout = 2.0  # секунды, для проверки stop_event в цикле

    @staticmethod
    def _build_crypto(cfg: ClientConfig) -> CryptoEngine:
        return CryptoEngine(
            private_key_b64=cfg.private_key_b64,
            peer_public_key_b64=cfg.peer.public_key_b64,
            preshared_key_b64=cfg.peer.preshared_key_b64,
        )

    # ---------------- Жизненный цикл ----------------

    def start(self):
        self.log.info(f"Запуск VPN-клиента (config: {self.config_path})")
        self.log.info(f"Публичный ключ клиента: {self.crypto.public_key_b64}")
        self.log.info(f"Peer endpoint: {self.config.peer.endpoint}")

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self.socket_timeout)

        self.tun.open()

        self._install_signal_handlers()

        self._recv_thread = threading.Thread(
            target=self._recv_loop, name="wg_emu-recv", daemon=True
        )
        self._send_thread = threading.Thread(
            target=self._keepalive_loop, name="wg_emu-keepalive", daemon=True
        )
        self._recv_thread.start()
        self._send_thread.start()

        self.log.info("Клиент запущен. Ожидание событий... (Ctrl+C для остановки)")

        # Основной поток просто ждёт сигнала остановки
        try:
            while not self._stop_event.is_set():
                time.sleep(0.5)
        finally:
            self._shutdown()

    def stop(self):
        self.log.info("Получен запрос на остановку клиента")
        self._stop_event.set()

    def _shutdown(self):
        self.log.info("Останавливаю клиент и освобождаю ресурсы...")
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self.tun.close()
        self.log.info("Клиент остановлен")

    def _install_signal_handlers(self):
        def _handler(signum, frame):
            sig_name = signal.Signals(signum).name
            self.log.info(f"Получен сигнал {sig_name}, инициирую graceful shutdown")
            self.stop()

        signal.signal(signal.SIGINT, _handler)
        # SIGTERM недоступен на Windows в некоторых версиях, поэтому обёрнуто
        try:
            signal.signal(signal.SIGTERM, _handler)
        except (AttributeError, ValueError):
            self.log.debug("SIGTERM недоступен на этой платформе, пропускаю")

    # ---------------- Отправка / приём пакетов ----------------

    def send_data(self, payload: bytes):
        """Шифрует и отправляет полезную нагрузку пиру."""
        with self._reload_lock:
            sock = self._sock
            crypto = self.crypto
            endpoint = self.config.peer.endpoint

        if sock is None:
            self.log.error("Сокет не инициализирован, отправка невозможна")
            return

        try:
            packet = crypto.encrypt(payload)
            sock.sendto(packet, endpoint)
            self.log.debug(f"Отправлено {len(packet)} байт на {endpoint}")
        except (OSError, socket.error) as e:
            self.log.error(f"Сетевая ошибка при отправке: {e}")
        except Exception as e:
            self.log.error(f"Ошибка шифрования при отправке: {e}")

    def _keepalive_loop(self, interval: float = 25.0):
        """Периодически отправляет keepalive-пакет, как это делает WireGuard."""
        while not self._stop_event.is_set():
            self.send_data(b"\x00")  # пустой keepalive-пакет
            self.log.debug("Keepalive отправлен")
            self._stop_event.wait(interval)

    def _recv_loop(self):
        while not self._stop_event.is_set():
            with self._reload_lock:
                sock = self._sock
                crypto = self.crypto

            if sock is None:
                self._stop_event.wait(0.5)
                continue

            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if self._stop_event.is_set():
                    break
                self.log.error(f"Ошибка сокета при приёме: {e}")
                continue

            try:
                plaintext = crypto.decrypt(data)
            except ValueError as e:
                self.log.warning(f"Отброшен некорректный/повреждённый пакет от {addr}: {e}")
                continue
            except Exception as e:
                self.log.error(f"Неожиданная ошибка расшифровки пакета от {addr}: {e}")
                continue

            if plaintext == b"\x00":
                self.log.debug(f"Получен keepalive от {addr}")
                continue

            self.log.info(f"Получено {len(plaintext)} байт полезных данных от {addr}")
            self._handle_incoming_payload(plaintext, addr)

    def _handle_incoming_payload(self, payload: bytes, addr):
        """
        Место для передачи расшифрованных данных в TUN-интерфейс /
        стек IP. В данной заглушке — просто логируем.
        """
        self.log.debug(f"[TUN-заглушка] payload -> локальный интерфейс: {payload[:64]!r}")

    # ---------------- Перезагрузка конфигурации ----------------

    def reload_config(self, new_path: Optional[Path] = None):
        """
        Перечитывает конфигурацию (и, при необходимости, ключи/эндпоинт)
        без остановки клиента. Потокобезопасно за счёт _reload_lock.
        """
        path = new_path or self.config_path
        self.log.info(f"Перезагрузка конфигурации из {path}...")

        try:
            new_config = ClientConfig.load(path)
            new_crypto = self._build_crypto(new_config)
        except Exception as e:
            self.log.error(f"Не удалось перезагрузить конфигурацию: {e}. Оставляю прежнюю.")
            return False

        with self._reload_lock:
            old_endpoint = self.config.peer.endpoint
            self.config = new_config
            self.crypto = new_crypto
            self.config_path = path
            self.tun = TunStub(self.config.address, self.config.peer.allowed_ips, self.log)

        self.log.info(
            f"Конфигурация перезагружена. Endpoint: {old_endpoint} -> {self.config.peer.endpoint}"
        )
        self.tun.open()
        return True


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Учебный VPN-клиент, эмулирующий базовые принципы WireGuard "
                     "(X25519 ECDH + ChaCha20-Poly1305 поверх UDP)."
    )
    parser.add_argument(
        "--config", "-c",
        type=Path,
        default=Path("config.json"),
        help="Путь к конфигурационному файлу (config.json или wg0.conf). "
             "По умолчанию: config.json",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Включить подробное (DEBUG) логирование",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if not args.config.exists():
        log.error(f"Файл конфигурации не найден: {args.config}")
        sys.exit(1)

    try:
        client = VPNClient(args.config, logger=log)
    except Exception as e:
        log.error(f"Ошибка инициализации клиента: {e}")
        sys.exit(1)

    try:
        client.start()
    except Exception as e:
        log.exception(f"Критическая ошибка выполнения: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

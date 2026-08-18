#!/usr/bin/env python3
"""Update the public Chapter Checker access list for an owner-triggered workflow."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn


APP_ID = "pond8611.chapter-checker"
ROOT_KEYS = {
    "schema_version",
    "app_id",
    "revision",
    "updated_utc",
    "minimum_version",
    "devices",
}
DEVICE_KEYS = {"device_hash", "status", "label", "message"}
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
UTC_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_ACCESS_BYTES = 1024 * 1024
MAX_ACCESS_REVISION = 9007199254740991


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def clean_text(value: str, limit: int, field: str) -> str:
    try:
        utf16_units = len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError:
        fail(f"{field} ไม่ถูกต้อง")
    if utf16_units > limit or any(ord(char) < 32 for char in value):
        fail(f"{field} ไม่ถูกต้อง")
    return value


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            fail(f"พบ key ซ้ำ: {key}")
        result[key] = value
    return result


def is_strict_utc(value: object) -> bool:
    if not isinstance(value, str) or not UTC_PATTERN.fullmatch(value):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value


def validate_document(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != ROOT_KEYS:
        fail("access.json มีโครงสร้าง root ไม่ถูกต้อง")
    schema_version = document.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
        or document.get("app_id") != APP_ID
    ):
        fail("access.json ไม่ตรงโปรแกรมหรือ schema")
    revision = document.get("revision")
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision <= 0
        or revision > MAX_ACCESS_REVISION
    ):
        fail("revision ต้องเป็นจำนวนเต็มบวก")
    version_match = VERSION_PATTERN.fullmatch(str(document.get("minimum_version", "")))
    if not version_match or any(int(part) > 2147483647 for part in version_match.groups()):
        fail("minimum_version ต้องเป็น x.y.z")
    if not is_strict_utc(document.get("updated_utc")):
        fail("updated_utc ไม่ถูกต้อง")
    devices = document.get("devices")
    if not isinstance(devices, list) or len(devices) > 10000:
        fail("devices ไม่ถูกต้องหรือมากเกินไป")

    seen: set[str] = set()
    for device in devices:
        if not isinstance(device, dict) or set(device) != DEVICE_KEYS:
            fail("รายการเครื่องมีโครงสร้างไม่ถูกต้อง")
        device_hash = device.get("device_hash")
        if not isinstance(device_hash, str) or not HASH_PATTERN.fullmatch(device_hash):
            fail("device_hash ไม่ถูกต้อง")
        if device_hash in seen:
            fail("พบ device_hash ซ้ำ")
        seen.add(device_hash)
        if device.get("status") not in {"allowed", "blocked"}:
            fail("status ต้องเป็น allowed หรือ blocked")
        if not isinstance(device.get("label"), str) or not isinstance(device.get("message"), str):
            fail("label และ message ต้องเป็นข้อความ")
        clean_text(device["label"], 100, "label")
        clean_text(device["message"], 240, "message")
    return document


def update(path: Path, operation: str, device_hash: str, label: str, message: str) -> bool:
    if operation not in {"allow", "block", "remove"}:
        fail("operation ไม่รองรับ")
    device_hash = device_hash.strip().lower()
    if not HASH_PATTERN.fullmatch(device_hash):
        fail("รหัสเครื่องต้องเป็น SHA-256 ตัวพิมพ์เล็ก 64 ตัว")
    label = clean_text(label.strip(), 100, "label")
    message = clean_text(message.strip(), 240, "message")

    raw = path.read_bytes()
    if len(raw) > MAX_ACCESS_BYTES:
        fail("access.json ใหญ่เกินขอบเขต")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("access.json ไม่ใช่ UTF-8 ที่ถูกต้อง")
    document = validate_document(json.loads(text, object_pairs_hook=reject_duplicate_pairs))
    devices = list(document["devices"])
    previous = next((item for item in devices if item["device_hash"] == device_hash), None)
    devices = [item for item in devices if item["device_hash"] != device_hash]
    if operation != "remove":
        devices.append(
            {
                "device_hash": device_hash,
                "status": "allowed" if operation == "allow" else "blocked",
                "label": label,
                "message": message,
            }
        )
    devices.sort(key=lambda item: item["device_hash"])

    current = next((item for item in devices if item["device_hash"] == device_hash), None)
    if previous == current:
        print("ACCESS_NO_CHANGE")
        return False

    document["devices"] = devices
    document["revision"] += 1
    document["updated_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    validate_document(document)
    output = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if len(output.encode("utf-8")) > MAX_ACCESS_BYTES:
        fail("access.json หลังแก้ใหญ่เกินขอบเขต")
    path.write_text(
        output,
        encoding="utf-8",
        newline="\n",
    )
    print(f"ACCESS_UPDATED revision={document['revision']} operation={operation}")
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        fail("usage: update_access.py FILE allow|block|remove DEVICE_HASH LABEL MESSAGE")
    update(Path(argv[1]), argv[2], argv[3], argv[4], argv[5])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

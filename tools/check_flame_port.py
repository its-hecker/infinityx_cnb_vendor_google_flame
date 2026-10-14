#!/usr/bin/env python3
"""Check the Flame install graph and provenance of the transplanted Coral port."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile

from apk_resource_reader import xml as apk_xml
from keymaster_elf import Elf

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def check(device):
    provenance = json.loads((ROOT / "tools/flame-port-provenance.json").read_text())
    for path, expected in provenance["donor_payload_sha256"].items():
        require(digest(ROOT / path) == expected, f"Coral payload changed: {path}")

    # Compare Git index blobs, including LFS pointers, without requiring radio
    # downloads merely to validate the source checkout.
    preserved = provenance["flame_preserved_git_blobs"]
    entries = subprocess.check_output([
        "git", "-C", str(ROOT), "ls-files", "--stage", "--", *preserved], text=True)
    indexed = {row.split("\t", 1)[1]: row.split()[1] for row in entries.splitlines()}
    for path, expected in preserved.items():
        require(indexed.get(path) == expected, f"Flame baseline changed: {path}")
        data = (ROOT / path).read_bytes()
        # Checkout filters materialize radio LFS pointers as binary images.
        # Their index OIDs above are checked; inspect normal files here too.
        if not path.startswith("radio/"):
            actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            require(actual == expected, f"Uncommitted Flame baseline edit: {path}")

    bp = (ROOT / "Android.bp").read_text()
    names = re.findall(r'\bname:\s*"([^"]+)"', bp)
    require(len(names) == len(set(names)), "Duplicate vendor module names")
    for path in set(re.findall(r'"(proprietary/[^"*]+)"', bp)):
        require((ROOT / path).is_file(), f"Missing vendor prebuilt: {path}")
    vendor = (ROOT / "flame-vendor.mk").read_text()
    for path in re.findall(r"vendor/google/flame/([^\s:]+):", vendor):
        require((ROOT / path).is_file(), f"Missing vendor copy source: {path}")
    require("vendor/google/coral" not in vendor, "Coral vendor source path remains")
    require("PixelCameraServicesFlame" in names and "PixelCameraServicesCoral" not in names,
            "Wrong camera-services variant")
    for module in ("OsloFeedback", "MotionSenseBridgePrebuilt", "PixelLiveWallpaper",
                   "android.hardware.biometrics.face@1.0-service.google",
                   "manifest_face.xml", "libautocalsolvers"):
        require(module in names and re.search(r"^    " + re.escape(module) + r"(?:\s|$)", vendor, re.M),
                f"Missing install entry: {module}")
    oslo = bp[bp.index('name: "OsloFeedback"'):]
    oslo = oslo[:oslo.index("\n}")]
    require('certificate: "platform"' in oslo and "system_ext_specific: true" in oslo,
            "OsloFeedback signing/partition changed")

    product = (device / "lineage_flame.mk").read_text()
    board = (device / "flame/BoardConfig.mk").read_text()
    hardware = (device / "flame/device.mk").read_text()
    common = (device / "device-common.mk").read_text()
    for setting in ("INFINITY_BUILD := flame", "PRODUCT_DEVICE := flame",
                    "PRODUCT_NAME := lineage_flame", "TARGET_FACE_UNLOCK_SUPPORTED := false",
                    "vendor/google/flame/flame-vendor.mk"):
        require(setting in product, f"Missing Flame product setting: {setting}")
    require("TARGET_BOOTLOADER_BOARD_NAME := flame" in board, "Wrong bootloader target")
    require("TARGET_SCREEN_HEIGHT := 2280" in hardware and "TARGET_SCREEN_WIDTH := 1080" in hardware,
            "Wrong Flame display dimensions")
    require("//vendor/google/flame:libsdsprpc" in hardware, "Wrong CHRE namespace")
    for package in ("libcamera2ndk_v33_face", "libstagefright_foundation-v33", "libcrypto-v33",
                    "android.hardware.thermal@2.0.vendor:64", "android.hardware.biometrics.face@1.0.vendor:64"):
        require(package in hardware, f"Missing Face runtime package: {package}")
    for package in ("GoogleParts", "GoogleOsloSystemUIOverlay"):
        require(package in common, f"Missing Motion Sense package: {package}")
    require("android.hardware.biometrics.face.xml" in hardware, "Face feature permission missing")

    face = Elf((ROOT / "proprietary/vendor/bin/hw/android.hardware.biometrics.face@1.0-service.google").read_bytes())
    needed = face.needed()
    require({"libcamera2ndk_face.so", "libstagefright_foundation-v33.so", "libbase-v33.so"} <= set(needed),
            "Face HAL legacy camera/handler ABI binding missing")
    require("libcamera2ndk_vendor.so" not in needed, "Face HAL loads modern camera ABI")
    service = Elf((ROOT / "proprietary/vendor/bin/hw/android.hardware.keymaster@4.1-service.citadel").read_bytes())
    impl = Elf((ROOT / "proprietary/vendor/lib64/android.hardware.keymaster@4.1-impl.nos.so").read_bytes())
    require(service.needed()[0] == "libcrypto-v33.so", "Citadel service must load legacy crypto first")
    require("libcrypto-v33.so" in impl.needed() and
            not {"libcrypto.so", "libcrypto_shim.so"} & set(impl.needed()), "Wrong Keymaster crypto ABI")
    rc = (ROOT / "proprietary/vendor/etc/init/android.hardware.biometrics.face@1.0-service.google.rc").read_text()
    require("interface android.hardware.biometrics.face@1.0::IBiometricsFace default" in rc,
            "Face HAL restart interface missing")
    ET.parse(ROOT / "proprietary/vendor/etc/vintf/manifest/manifest_face.xml")
    grants = ET.parse(ROOT / "proprietary/system_ext/etc/permissions/privapp-permissions-google-se-lineage.xml")
    require(grants.find(".//privapp-permissions[@package='com.google.oslo']/permission[@name='android.permission.READ_DEVICE_CONFIG']") is not None,
            "Oslo READ_DEVICE_CONFIG privilege missing")
    with zipfile.ZipFile(ROOT / "proprietary/system_ext/priv-app/OsloFeedback/OsloFeedback.apk") as apk:
        require(apk_xml(apk.read("AndroidManifest.xml")).get("package") == "com.google.oslo",
                "Wrong Oslo package")
        require("classes.dex" in apk.namelist() and "classes2.dex" in apk.namelist(),
                "Motion Lab DEX payload missing")
    return (f"Coral payload identity: PASS ({len(provenance['donor_payload_sha256'])} files)\n"
            f"Flame camera/firmware/radio baseline: PASS ({len(preserved)} Git blobs)\n"
            "Vendor sources, unique modules, install graph and product selection: PASS\n"
            "Face HAL, Citadel crypto, init/VINTF and Oslo permissions/APK: PASS\n"
            "Source preflight: PASS; full Soong/build and Flame phone testing still required\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-root", required=True, type=Path)
    args = parser.parse_args()
    print(check(args.device_root), end="")


if __name__ == "__main__":
    main()

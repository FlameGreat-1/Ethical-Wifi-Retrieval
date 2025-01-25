import subprocess
import sys
import os
import logging
import hashlib
import requests
from typing import List, Tuple
import ctypes
import platform
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


class SecurityCheck:
    def __init__(self):
        self.logger = logging.getLogger("security_check_log")
        self.logger = logging.getLogger("security_check_log")
        self.app_signature = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdefghijklmnopqrstuvwxyz"  # Replace with actual app signature
        self.public_key = x509.load_pem_x509_certificate(self.app_signature.encode()).public_key()


    def is_device_secure(self) -> bool:
        self.logger.info("Performing device security check")
        if sys.platform.startswith("linux"):
            return self._check_android_security()
        elif sys.platform == "darwin":
            return self._check_ios_security()
        elif sys.platform == "win32":
            return self._check_windows_security()
        else:
            self.logger.error(f"Unsupported platform: {sys.platform}")
            raise NotImplementedError("Unsupported platform")

    def _check_android_security(self) -> bool:
        checks: List[Tuple[str, bool]] = [
            ("Root check", not self._is_rooted()),
            ("Developer options check", not self._developer_options_enabled()),
            ("Unknown sources check", not self._unknown_sources_enabled()),
            ("App integrity check", self.verify_app_integrity()),
            ("Secure boot check", self.check_secure_boot())
        ]
        return self._process_checks(checks)

    def _check_ios_security(self) -> bool:
        checks: List[Tuple[str, bool]] = [
            ("Jailbreak check", not self._is_jailbroken()),
            ("Developer mode check", not self._developer_mode_enabled()),
            ("App integrity check", self.verify_app_integrity()),
            ("Secure boot check", self.check_secure_boot())
        ]
        return self._process_checks(checks)

    def _check_windows_security(self) -> bool:
        checks: List[Tuple[str, bool]] = [
            ("Admin privileges check", not self._is_admin()),
            ("Developer mode check", not self._windows_developer_mode_enabled()),
            ("App integrity check", self.verify_app_integrity()),
            ("Secure boot check", self.check_secure_boot())
        ]
        return self._process_checks(checks)

    def _process_checks(self, checks: List[Tuple[str, bool]]) -> bool:
        for check_name, result in checks:
            self.logger.info(f"{check_name}: {'Passed' if result else 'Failed'}")
            if not result:
                return False
        return True

    def _is_rooted(self) -> bool:
        root_paths = ["/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su"]
        return any(os.path.exists(path) for path in root_paths)

    def _developer_options_enabled(self) -> bool:
        try:
            result = subprocess.run(["adb", "shell", "settings", "get", "global", "development_settings_enabled"], capture_output=True, text=True, check=True)
            return result.stdout.strip() == "1"
        except subprocess.CalledProcessError:
            self.logger.error("Failed to check developer options")
            return False

    def _unknown_sources_enabled(self) -> bool:
        try:
            result = subprocess.run(["adb", "shell", "settings", "get", "secure", "install_non_market_apps"], capture_output=True, text=True, check=True)
            return result.stdout.strip() == "1"
        except subprocess.CalledProcessError:
            self.logger.error("Failed to check unknown sources")
            return False

    def _is_jailbroken(self) -> bool:
        jailbreak_paths = ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib"]
        return any(os.path.exists(path) for path in jailbreak_paths)

    def _developer_mode_enabled(self) -> bool:
        try:
            result = subprocess.run(["defaults", "read", "com.apple.dt.Xcode", "IDEXcodeVersionForAgreedToGMLicense"], capture_output=True, text=True, check=True)
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            self.logger.error("Failed to check developer mode")
            return False

    def _is_admin(self) -> bool:
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    def _windows_developer_mode_enabled(self) -> bool:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock")
            value, _ = winreg.QueryValueEx(key, "AllowDevelopmentWithoutDevLicense")
            return value == 1
        except WindowsError:
            self.logger.error("Failed to check Windows developer mode")
            return False

    def verify_app_integrity(self) -> bool:
        try:
            with open(sys.executable, 'rb') as f:
                app_content = f.read()
                app_hash = hashlib.sha256(app_content).hexdigest()

            # Get the signature from a predefined location in the executable
            signature_offset = -256  # Assume signature is stored in the last 256 bytes
            signature = app_content[signature_offset:]
            
            # Verify the signature
            try:
                self.public_key.verify(
                    signature,
                    app_hash.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                self.logger.info("App signature verification successful")
                return True
            except InvalidSignature:
                self.logger.error("App signature verification failed")
                return False

        except Exception as e:
            self.logger.error(f"App integrity check failed: {str(e)}")
            return False

    def check_secure_boot(self) -> bool:
        if sys.platform.startswith("linux"):
            return self._check_android_secure_boot()
        elif sys.platform == "darwin":
            return self._check_ios_secure_boot()
        elif sys.platform == "win32":
            return self._check_windows_secure_boot()
        else:
            self.logger.error(f"Secure boot check not implemented for platform: {sys.platform}")
            return False

    def _check_android_secure_boot(self) -> bool:
        try:
            # Check verified boot state
            boot_state = subprocess.run(["getprop", "ro.boot.verifiedbootstate"], capture_output=True, text=True, check=True).stdout.strip()
            if boot_state != "green":
                self.logger.warning(f"Verified boot state is not green: {boot_state}")
                return False

            # Check if dm-verity is enabled
            verity_mode = subprocess.run(["getprop", "ro.boot.veritymode"], capture_output=True, text=True, check=True).stdout.strip()
            if verity_mode != "enforcing":
                self.logger.warning(f"dm-verity is not enforcing: {verity_mode}")
                return False

            # Check if AVB (Android Verified Boot) is enabled
            avb_version = subprocess.run(["getprop", "ro.boot.avb_version"], capture_output=True, text=True, check=True).stdout.strip()
            if not avb_version:
                self.logger.warning("AVB is not enabled")
                return False

            self.logger.info("Android secure boot checks passed")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to check Android secure boot: {str(e)}")
            return False

    def _check_ios_secure_boot(self) -> bool:
        try:
            # Check if the device is jailbroken
            jailbreak_files = ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib"]
            if any(os.path.exists(path) for path in jailbreak_files):
                self.logger.warning("Device appears to be jailbroken")
                return False

            # Check if the device has a passcode set
            passcode_status = subprocess.run(["defaults", "read", "/Library/Preferences/com.apple.restrictionspassword.plist", "RestrictionsPasswordKey"], capture_output=True, text=True)
            if passcode_status.returncode != 0:
                self.logger.warning("Device does not have a passcode set")
                return False

            # Check if data protection is enabled
            data_protection_status = subprocess.run(["defaults", "read", "/Library/Preferences/com.apple.mobile.ldid.plist", "DataProtectionEnabled"], capture_output=True, text=True)
            if data_protection_status.returncode != 0 or data_protection_status.stdout.strip() != "1":
                self.logger.warning("Data protection is not enabled")
                return False

            self.logger.info("iOS secure boot checks passed")
            return True
        except Exception as e:
            self.logger.error(f"Failed to check iOS secure boot: {str(e)}")
            return False

    def _check_windows_secure_boot(self) -> bool:
        try:
            # Check if Secure Boot is enabled
            secure_boot_status = subprocess.run(["powershell", "-Command", "Confirm-SecureBootUEFI"], capture_output=True, text=True, check=True)
            if secure_boot_status.stdout.strip().lower() != "true":
                self.logger.warning("Secure Boot is not enabled")
                return False

            # Check if BitLocker is enabled on the system drive
            bitlocker_status = subprocess.run(["manage-bde", "-status", "C:"], capture_output=True, text=True, check=True)
            if "Protection On" not in bitlocker_status.stdout:
                self.logger.warning("BitLocker is not enabled on the system drive")
                return False

            # Check if Windows Defender is enabled and up-to-date
            defender_status = subprocess.run(["powershell", "-Command", "Get-MpComputerStatus"], capture_output=True, text=True, check=True)
            defender_info = dict(line.split(':') for line in defender_status.stdout.splitlines() if ':' in line)
            if defender_info.get("AntivirusEnabled", "").strip().lower() != "true":
                self.logger.warning("Windows Defender is not enabled")
                return False
            if defender_info.get("AntivirusSignatureAge", "").strip() != "0":
                self.logger.warning("Windows Defender signatures are not up-to-date")
                return False

            self.logger.info("Windows secure boot checks passed")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to check Windows secure boot: {str(e)}")
            return False

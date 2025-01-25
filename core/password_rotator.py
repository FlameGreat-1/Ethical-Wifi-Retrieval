
import secrets
import string
import schedule
import time
from threading import Thread

class PasswordRotator:
    def __init__(self, wifi_manager):
        self.wifi_manager = wifi_manager
        self.rotation_thread = Thread(target=self._run_scheduler)
        self.rotation_thread.daemon = True

    def start(self):
        schedule.every().day.at("03:00").do(self.rotate_all_passwords)  # Rotate passwords daily at 3 AM
        self.rotation_thread.start()

    def _run_scheduler(self):
        while True:
            schedule.run_pending()
            time.sleep(60)

    def rotate_all_passwords(self):
        ssids = self.wifi_manager.get_all_ssids()
        for ssid in ssids:
            self.rotate_password(ssid)

    def rotate_password(self, ssid):
        new_password = self.generate_strong_password()
        try:
            self.wifi_manager.update_password(ssid, new_password)
            print(f"Password rotated for {ssid}")
        except Exception as e:
            print(f"Failed to rotate password for {ssid}: {str(e)}")

    def generate_strong_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for i in range(20))


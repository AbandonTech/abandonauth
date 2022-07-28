import smtplib
import ssl

from classy_config import ConfigValue

from .email_client import EmailClient


class SmtpClient(EmailClient):
    def __init__(
            self,
            server=ConfigValue("EMAIL_SERVER", str),
            email=ConfigValue("EMAIL_ADDRESS", str),
            password=ConfigValue("EMAIL_PASSWORD", str)
    ):
        self._smtp_domain = server
        self._email = email
        self._password = password
        self._ssl_ctx = ssl.create_default_context()

    def send(self, subject: str, message: str, recipient_email: str) -> None:
        formatted_message = f"Subject: {subject}\n\n{message}"

        with smtplib.SMTP_SSL(
                self._smtp_domain, 465, context=self._ssl_ctx) as server:
            server.login(self._email, self._password)
            server.sendmail(self._email, recipient_email, formatted_message)

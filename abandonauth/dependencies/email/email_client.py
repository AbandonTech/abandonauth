from abc import ABC, abstractmethod


class EmailClient(ABC):
    @abstractmethod
    def send(self, subject: str, message: str, recipient_email: str) -> None:
        raise NotImplementedError()

from passlib import pwd
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_data(plain_data: str, hashed_data: str) -> bool:
    return pwd_context.verify(plain_data, hashed_data)


def get_hashed_data(data: str) -> str:
    return pwd_context.hash(data)


def generate_refresh_token() -> str:
    return pwd.genword(entropy=122, charset="ascii_72")

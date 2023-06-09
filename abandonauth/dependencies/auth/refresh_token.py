from passlib import pwd
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_refresh_token(plain_token: str, hashed_token: str) -> bool:
    return pwd_context.verify(plain_token, hashed_token)


def get_refresh_token_hash(token: str) -> str:
    return pwd_context.hash(token)


def generate_refresh_token() -> str:
    return pwd.genword(entropy=122, charset="ascii_72")

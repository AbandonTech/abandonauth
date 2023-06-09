from passlib import pwd
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_refresh_token(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_refresh_token_hash(password):
    return pwd_context.hash(password)


def generate_refresh_token():
    return pwd.genword(entropy=64, charset="ascii_72")

try:
    from passlib.context import CryptContext
except ModuleNotFoundError:
    CryptContext = None

if CryptContext:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
else:
    pwd_context = None


def hash_password(password: str) -> str:
    if not pwd_context:
        raise RuntimeError("passlib[bcrypt] nao instalado. Instale requirements/base.txt.")
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    if not pwd_context:
        raise RuntimeError("passlib[bcrypt] nao instalado. Instale requirements/base.txt.")
    return pwd_context.verify(plain_password, password_hash)

try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
except ModuleNotFoundError:
    Limiter = None

    def get_remote_address(_request=None):
        return "local"

from app.core.config.settings import settings

RATE_LIMIT_ANALISAR = settings.rate_limit_analisar
RATE_LIMIT_ANALISAR_SITE = settings.rate_limit_analisar_site
RATE_LIMIT_OSINT = settings.rate_limit_osint

class NoopLimiter:
    def limit(self, _limit_value):
        def decorator(func):
            return func
        return decorator


limiter = Limiter(key_func=get_remote_address) if Limiter else NoopLimiter()

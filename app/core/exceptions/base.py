class AppError(Exception):
    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class DomainError(AppError):
    status_code = 400
    code = "domain_error"


class ExternalServiceError(AppError):
    status_code = 502
    code = "external_service_error"


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"

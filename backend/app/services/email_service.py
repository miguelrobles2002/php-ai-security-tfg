import logging

logger = logging.getLogger(__name__)


def send_verification_email(to_email: str, token: str) -> bool:
    logger.info("send_verification_email llamado pero desactivado (to=%s)", to_email)
    return False
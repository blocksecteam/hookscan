import logging


def _get_fake_logger():
    logger = logging.getLogger("fake_logger")
    logger.setLevel(logging.CRITICAL)
    return logger


runtime_logger = _get_fake_logger()

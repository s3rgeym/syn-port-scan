import logging

from .ansi import ANSI


class ColorHandler(logging.StreamHandler):
    _log_colors: dict[int, str] = {
        logging.DEBUG: ANSI.GREY,
        logging.INFO: ANSI.GREEN,
        logging.WARNING: ANSI.MAGENTA,
        logging.ERROR: ANSI.RED,
        logging.CRITICAL: ANSI.BRIGHT_RED,
    }

    _fmt = logging.Formatter(
        "%(threadName)-24s - %(levelname)-8s - %(message)s"
    )

    def format(self, record: logging.LogRecord) -> str:
        message = self._fmt.format(record)
        return f"{self._log_colors[record.levelno]}{message}{ANSI.RESET}"


logger = logging.getLogger(__name__.split(".")[0])
logger.addHandler(ColorHandler())

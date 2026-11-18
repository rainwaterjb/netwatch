"""Logging setup: plain text (default) or one JSON object per line (LOG_FORMAT=json),
which Grafana Alloy (for Loki) or Vector can parse without extra rules."""
import json
import logging
import os
import time

RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record):
        out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
               "level": record.levelname.lower(), "logger": record.name, "msg": record.getMessage()}
        out.update({k: v for k, v in vars(record).items() if k not in RESERVED and not k.startswith("_")})
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str, ensure_ascii=False)


def setup():
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    root = logging.getLogger()
    if getattr(root, "_netwatch_configured", False):
        return
    handler = logging.StreamHandler()
    if os.getenv("LOG_FORMAT", "text").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.handlers[:] = [handler]
    root.setLevel(level)
    root._netwatch_configured = True

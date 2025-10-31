import logging
from urllib.parse import parse_qs, urlparse

_logger = logging.getLogger("peas.http")
if not _logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[HTTP] %(message)s"))
    _logger.addHandler(handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


def _extract_params(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    return {
        "device_id": qs.get("DeviceId", [None])[0],
        "device_type": qs.get("DeviceType", [None])[0],
        "user": qs.get("User", [None])[0],
    }


def _normalize_header_name(name):
    return name.lower().replace("-", "")


def _normalize_headers(headers):
    normal = {}
    if headers is None:
        return normal
    if isinstance(headers, dict):
        items = headers.items()
    else:
        try:
            items = headers
        except TypeError:
            return normal
    for key, value in items:
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            val = value[0] if value else None
        else:
            val = value
        if isinstance(key, bytes):
            key = key.decode("ascii", "ignore")
        if isinstance(val, bytes):
            val = val.decode("utf-8", "ignore")
        if key:
            normal[_normalize_header_name(key)] = val
    return normal


def log_http_request(method, url, *, device_id=None, device_type=None, user=None):
    params = _extract_params(url)
    device_id = device_id or params["device_id"]
    device_type = device_type or params["device_type"]
    user = user or params["user"]

    parts = [method.upper(), url]
    if user:
        parts.append(f"user={user}")
    if device_id:
        parts.append(f"device_id={device_id}")
    if device_type:
        parts.append(f"device_type={device_type}")

    _logger.info(" | ".join(parts))


def log_http_response(method, url, status, headers=None):
    normalized = _normalize_headers(headers)
    message = f"{method.upper()} {url} -> {status}"
    _logger.info(message)

    state = normalized.get("xmsdeviceaccessstate")
    reason = normalized.get("xmsdeviceaccessstatereason")
    if state:
        warn_msg = f"Device access state: {state}"
        if reason:
            warn_msg += f" ({reason})"
        _logger.warning(warn_msg)

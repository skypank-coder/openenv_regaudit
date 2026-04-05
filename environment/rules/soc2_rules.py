from typing import Dict

SOC2_RULES: Dict[str, dict] = {
    "SOC2-CC6.1": {
        "description": "Logical access controls: authentication endpoints must implement rate limiting and account lockout to prevent brute-force attacks.",
        "examples": ["def login():  # no lockout, no rate limit"],
        "severity_hint": "high",
        "keywords": ["login", "authenticate", "lockout", "rate_limit"],
    },
    "SOC2-CC7.2": {
        "description": "System monitoring: missing structured logging or audit trails for sensitive operations (login, data export, admin actions) violates monitoring requirements.",
        "examples": ["# no audit log on delete", "User.delete()  # no event recorded"],
        "severity_hint": "medium",
        "keywords": ["delete", "admin", "audit", "log", "event"],
    },
}

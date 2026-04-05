from typing import Dict

GDPR_RULES: Dict[str, dict] = {
    "GDPR-ART5-1A": {
        "description": "Personal data must be processed lawfully. Logging PII (email, name, phone, user_id) to stdout or unprotected log files violates this principle.",
        "examples": ["logger.info(f'User {user.email} logged in')", "print(request.user.email)"],
        "severity_hint": "high",
        "keywords": ["email", "phone", "user_id", "logger", "print", "log"],
    },
    "GDPR-ART5-1C": {
        "description": "Data minimisation: APIs must not return more personal data than necessary. Returning password hashes, internal IDs, or full PII objects in public endpoints violates this.",
        "examples": ["return jsonify(user.__dict__)", "serializer = UserSerializer(user, many=False)  # includes password"],
        "severity_hint": "high",
        "keywords": ["password", "hash", "serializer", "jsonify", "__dict__", "to_dict"],
    },
    "GDPR-ART25": {
        "description": "Data protection by design: missing rate limiting on authentication endpoints enables credential stuffing, violating privacy by design.",
        "examples": ["@app.route('/login', methods=['POST'])  # no rate limit decorator"],
        "severity_hint": "medium",
        "keywords": ["login", "authenticate", "rate_limit", "limiter", "throttle"],
    },
    "GDPR-ART30": {
        "description": "Records of processing: database models storing personal data must include a data_retention or created_at field to support deletion workflows.",
        "examples": ["class User(Model):  # no created_at or deleted_at"],
        "severity_hint": "medium",
        "keywords": ["Model", "models.py", "created_at", "deleted_at", "retention"],
    },
    "GDPR-ART32": {
        "description": "Security of processing: plaintext secrets, disabled security middleware, or debug mode in production violates the requirement for appropriate technical measures.",
        "examples": ["SECRET_KEY = 'hardcoded'", "CSRF_ENABLED = False", "DEBUG = True"],
        "severity_hint": "critical",
        "keywords": ["SECRET_KEY", "DEBUG", "CSRF", "password", "settings.py"],
    },
}

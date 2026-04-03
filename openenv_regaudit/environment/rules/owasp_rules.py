from typing import Dict

OWASP_RULES: Dict[str, dict] = {
    "OWASP-A01": {
        "description": "Insecure direct object reference: using user-supplied IDs to access resources without verifying ownership (e.g. /users/{id} without checking request.user.id == id).",
        "examples": ["user = User.query.get(request.args['user_id'])", "obj = Model.objects.get(pk=pk)  # no ownership check"],
        "severity_hint": "high",
        "keywords": ["request.args", "pk=pk", "query.get", "objects.get", "user_id"],
    },
    "OWASP-A03": {
        "description": "SQL injection via raw query construction using string formatting or concatenation instead of parameterised queries.",
        "examples": ["db.execute(f\"SELECT * FROM users WHERE id = {user_id}\")", "cursor.execute('SELECT * FROM users WHERE name = ' + name)"],
        "severity_hint": "critical",
        "keywords": ["execute", "f\"SELECT", "f'SELECT", "+ name", "raw(", ".format("],
    },
    "OWASP-A05": {
        "description": "Security misconfiguration: CSRF protection disabled, debug error pages enabled, or permissive CORS in production.",
        "examples": ["CSRF_ENABLED = False", "WTF_CSRF_ENABLED = False", "app.debug = True"],
        "severity_hint": "high",
        "keywords": ["CSRF", "WTF_CSRF", "debug", "CORS", "ALLOWED_HOSTS"],
    },
    "OWASP-A04": {
        "description": "Unrestricted file upload: accepting file uploads without validating extension, MIME type, or file size enables remote code execution.",
        "examples": ["file = request.files['upload']", "file.save(os.path.join(UPLOAD_FOLDER, file.filename))"],
        "severity_hint": "high",
        "keywords": ["request.files", "file.save", "UPLOAD_FOLDER", "filename", "upload"],
    },
    "OWASP-A02": {
        "description": "Plaintext secrets: hardcoded API keys, database passwords, or session secrets in source code or config files.",
        "examples": ["DATABASE_URL = 'postgresql://user:password123@localhost'", "API_KEY = 'sk-live-abc123'"],
        "severity_hint": "critical",
        "keywords": ["DATABASE_URL", "API_KEY", "SECRET", "password", "token", "settings"],
    },
}

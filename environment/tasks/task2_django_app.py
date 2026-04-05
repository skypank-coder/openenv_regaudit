from typing import Dict, List

# Oracle check: Task 2: optimal 5-file combo covers 8/8 violations (max score: 0.84)

CODEBASE: Dict[str, str] = {
    "models.py": """from django.db import models

class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    # TODO add timestamps
    # GDPR-ART30 violation: missing created_at and deleted_at

    class Meta:
        db_table = 'auth_user'

    @classmethod
    def search_by_username(cls, username):
        # OWASP-A03 violation: raw SQL without parameterisation
        return cls.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")
""",

    "views.py": """from django.http import JsonResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from .models import User

def user_detail(request, pk):
    user = get_object_or_404(User, pk=pk)
    # OWASP-A01 violation: no ownership check
    return JsonResponse({'id': user.id, 'username': user.username, 'email': user.email})

def user_list(request):
    users = User.objects.all()
    return JsonResponse({'count': len(users)})

def profile(request):
    return JsonResponse({'profile': 'ok'})

def upload_document(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'method not allowed'}, status=405)
    f = request.FILES.get('document')
    if not f:
        return JsonResponse({'error': 'no file'}, status=400)
    # OWASP-A04 violation: no extension/MIME validation
    path = f'/tmp/{f.name}'
    with open(path, 'wb') as out:
        for chunk in f.chunks():
            out.write(chunk)
    return JsonResponse({'message': 'upload saved'})

def health(request):
    return JsonResponse({'status': 'healthy'})
    # RED-HERRING: log user email only when debugging (this is only in comment, not actual)
    # logger.info(f"Health check from {request.user.email}")

def logout(request):
    return JsonResponse({'message': 'logged out'})
""",

    "serializers.py": """from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # GDPR-ART5-1C violation: includes password in serialization
        fields = ['id', 'username', 'email', 'password', 'last_login']
        # RED-HERRING: in older versions, password used to be exposed here
        # This is now handled with a custom property (not shown) but comment remains
""",

    "middleware.py": """import logging

logger = logging.getLogger('myapp')

class AnalyticsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.process_request(request)

    def process_request(self, request):
        if request.user.is_authenticated:
            # GDPR-ART5-1A violation: logging PII email for analytics
            logger.debug(f'Analytics event: user_email={request.user.email}')
        return self.get_response(request)
""",

    "settings.py": """DEBUG = True
# GDPR-ART32 violation: debug True in production-ish config
SECRET_KEY = 'django-insecure-abc123xyz'
# OWASP-A02 violation: hardcoded secret key
ALLOWED_HOSTS = ['*']
# RED-HERRING: test key below is only for development (never used in production)
TEST_SECRET = 'test-key-only'
INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'rest_framework',
]
""",
}

GROUND_TRUTH: List[Dict] = [
    {"file": "models.py", "rule_id": "GDPR-ART30", "severity": "medium", "line_start": 8, "line_end": 8},
    {"file": "models.py", "rule_id": "OWASP-A03", "severity": "critical", "line_start": 16, "line_end": 16},
    {"file": "views.py", "rule_id": "OWASP-A01", "severity": "high", "line_start": 7, "line_end": 7},
    {"file": "views.py", "rule_id": "OWASP-A04", "severity": "high", "line_start": 23, "line_end": 23},
    {"file": "serializers.py", "rule_id": "GDPR-ART5-1C", "severity": "high", "line_start": 7, "line_end": 7},
    {"file": "middleware.py", "rule_id": "GDPR-ART5-1A", "severity": "high", "line_start": 14, "line_end": 14},
    {"file": "settings.py", "rule_id": "GDPR-ART32", "severity": "critical", "line_start": 1, "line_end": 1},
    {"file": "settings.py", "rule_id": "OWASP-A02", "severity": "critical", "line_start": 3, "line_end": 3},
]


def get_task() -> Dict:
    return {
        "task_id": "task2_django_app",
        "codebase": CODEBASE,
        "ground_truth": GROUND_TRUTH,
        "framework": ["GDPR", "OWASP"],
        "file_reads_remaining": 7,
        "max_steps": 30,
        "description": "Audit a Django REST API across 5 files for GDPR and OWASP violations.",
    }

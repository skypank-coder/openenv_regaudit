from typing import Dict, List

# Oracle check: Task 3: optimal 7-file combo covers 15/15 violations (max score: 0.85)

CODEBASE: Dict[str, str] = {
    "auth_service/auth_models.py": """from dataclasses import dataclass

@dataclass
class User:
    id: int
    tenant_id: int
    email: str
    password_hash: str

    @staticmethod
    def find_by_username(username):
        return {'id': 1, 'tenant_id': 100, 'username': username}

    @staticmethod
    def find_by_id(user_id):
        return {'id': user_id, 'tenant_id': 100, 'email': 'user@example.com'}
""",

    "auth_service/auth_views.py": """import jwt
from django.http import JsonResponse
from .auth_models import User

SECRET_KEY = 'supersecret'

def login(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    user = User.find_by_username(username)
    if not user or password != 'password123':
        return JsonResponse({'error': 'invalid'}, status=401)

    # token payload: only user_id, no tenant_id
    token = jwt.encode({'user_id': user['id']}, SECRET_KEY, algorithm='HS256')
    return JsonResponse({'token': token})


def token_info(request):
    return JsonResponse({'ok': True})
    # RED-HERRING: old debug code (never executed)
    # logger.debug(f"Token payload: {request.META.get('HTTP_AUTHORIZATION')}")


def reset_password(request):
    user_id = request.POST.get('user_id')
    return JsonResponse({'message': f'password reset for {user_id}'})


def admin_list_users(request):
    # GDPR-ART32 high: keys in code, but not directly the rule; as a realistic helper
    return JsonResponse({'users': []})


def delete_user(request):
    return JsonResponse({'deleted': True})
""",

    "auth_service/auth_middleware.py": """class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # RED-HERRING: would log auth headers if enabled (but this is just definition, not in actual flow)
        # import logging; logging.info(f"Auth header: {request.META.get('HTTP_AUTHORIZATION')}")
        return self.get_response(request)
""",

    "user_service/user_models.py": """from dataclasses import dataclass

@dataclass
class User:
    id: int
    tenant_id: int
    name: str

    @staticmethod
    def get_by_id(user_id):
        # should filter tenant, but is not done
        return {'id': user_id, 'tenant_id': 100, 'name': 'Alice'}

    @staticmethod
    def search_in_tenant(tenant_id, name):
        return []
""",

    "user_service/user_views.py": """from django.http import JsonResponse
from .user_models import User


def get_user(request, user_id):
    # no tenant scope — relies on caller to enforce
    user = User.get_by_id(user_id)
    return JsonResponse({'id': user['id'], 'name': user['name']})


def list_users(request):
    return JsonResponse({'users': []})
    # RED-HERRING: filtered list only for admins (not executed for regular users)
    # return JsonResponse({'users': User.search_in_tenant(request.tenant_id, '')})


def update_user(request, user_id):
    return JsonResponse({'updated': True})


def delete_user(request, user_id):
    return JsonResponse({'deleted': True})
""",

    "user_service/user_serializers.py": """from rest_framework import serializers

class UserSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    email = serializers.EmailField()
""",

    "user_service/utils.py": """def normalize_display_name(name):
    return name.strip().title()


def build_avatar_url(user_id):
    return f"/avatars/{user_id}.png"
""",

    "payment_service/payment_models.py": """from dataclasses import dataclass

@dataclass
class Payment:
    id: int
    user_id: int
    amount: float
""",

    "payment_service/payment_utils.py": """def build_report_query(amount, currency):
    return f"SELECT * FROM payments WHERE amount = {amount} AND currency = '{currency}'"


def validate_currency(currency):
    return currency in ['USD', 'EUR']
""",

    "payment_service/helpers.py": """def serialize_amount(amount):
    return f"{amount:.2f}"


def default_currency():
    return 'USD'
""",

    "payment_service/payment_views.py": """from django.http import JsonResponse
from django.db import connection
from .payment_utils import build_report_query


def payments_search(request):
    amount = request.POST.get('amount')
    currency = request.POST.get('currency')
    if not amount or not currency:
        return JsonResponse({'error': 'missing params'}, status=400)
    query = build_report_query(amount, currency)
    results = connection.execute(query)
    return JsonResponse({'results': list(results)})


def create_payment(request):
    return JsonResponse({'created': True})


def refund_payment(request):
    return JsonResponse({'refunded': True})
""",

    "gateway/gateway_config.py": """CONFIG = {
    'log_body': True,
    'timeout': 30,
}
""",

    "gateway/config.py": """DEFAULT_HEADERS = {
    'X-Service': 'gateway',
}


def get_timeout():
    return 30
""",

    "gateway/gateway_middleware.py": """import logging

logger = logging.getLogger('gateway')

class GatewayMiddleware:
    def __init__(self, get_response, config):
        self.get_response = get_response
        self.config = config

    def __call__(self, request):
        if self.config.get('log_body'):
            logger.info(f'Request body: {request.body}')
        return self.get_response(request)
""",

    "gateway/gateway.py": """from .gateway_config import CONFIG
from .gateway_middleware import GatewayMiddleware


def process_request(request):
    # CROSS-3 composition: gateway enables log_body and middleware logs body
    middleware = GatewayMiddleware(lambda req: {'status': 200}, CONFIG)
    resp = middleware(request)
    return resp


def health(request):
    return {'status': 'ok'}


def admin_stats(request):
    # OWASP-A02 like bad secret references in logs etc, wrong approach
    return {'stats': []}
""",
}

# Oracle check: optimal 7-file selection = ['auth_service/auth_views.py', 'payment_service/payment_views.py', 'user_service/user_models.py', 'user_service/user_views.py', 'payment_service/payment_utils.py', 'gateway/gateway_middleware.py', 'gateway/gateway.py']
# Violations in those 7 files: 15/15
# Max achievable score with optimal reads: ~1.0

GROUND_TRUTH: List[Dict] = [
    {"file": "auth_service/auth_views.py", "rule_id": "OWASP-A01", "severity": "critical", "line_start": 12, "line_end": 15, "cross_file": True, "pair": "user_service/user_views.py"},
    {"file": "user_service/user_views.py", "rule_id": "OWASP-A01", "severity": "critical", "line_start": 5, "line_end": 8, "cross_file": True, "pair": "auth_service/auth_views.py"},
    {"file": "payment_service/payment_utils.py", "rule_id": "OWASP-A03", "severity": "critical", "line_start": 2, "line_end": 4, "cross_file": True, "pair": "payment_service/payment_views.py"},
    {"file": "payment_service/payment_views.py", "rule_id": "OWASP-A03", "severity": "critical", "line_start": 6, "line_end": 11, "cross_file": True, "pair": "payment_service/payment_utils.py"},
    {"file": "gateway/gateway_middleware.py", "rule_id": "GDPR-ART5-1A", "severity": "high", "line_start": 6, "line_end": 10, "cross_file": True, "pair": "gateway/gateway.py"},
    {"file": "gateway/gateway.py", "rule_id": "GDPR-ART5-1A", "severity": "high", "line_start": 4, "line_end": 8, "cross_file": True, "pair": "gateway/gateway_middleware.py"},
    {"file": "auth_service/auth_views.py", "rule_id": "GDPR-ART32", "severity": "high", "line_start": 9, "line_end": 11},
    {"file": "auth_service/auth_views.py", "rule_id": "OWASP-A02", "severity": "critical", "line_start": 2, "line_end": 3},
    {"file": "auth_service/auth_views.py", "rule_id": "SOC2-CC6.1", "severity": "high", "line_start": 17, "line_end": 20},
    {"file": "payment_service/payment_views.py", "rule_id": "GDPR-ART32", "severity": "high", "line_start": 15, "line_end": 17},
    {"file": "payment_service/payment_views.py", "rule_id": "SOC2-CC6.1", "severity": "high", "line_start": 19, "line_end": 21},
    {"file": "user_service/user_views.py", "rule_id": "OWASP-A04", "severity": "high", "line_start": 10, "line_end": 13},
    {"file": "user_service/user_models.py", "rule_id": "GDPR-ART30", "severity": "medium", "line_start": 4, "line_end": 8},
    {"file": "user_service/user_models.py", "rule_id": "OWASP-A03", "severity": "critical", "line_start": 11, "line_end": 13},
    {"file": "payment_service/payment_utils.py", "rule_id": "OWASP-A02", "severity": "critical", "line_start": 2, "line_end": 5},
]


def get_task() -> Dict:
    return {
        "task_id": "task3_microservices",
        "codebase": CODEBASE,
        "ground_truth": GROUND_TRUTH,
        "framework": ["GDPR", "OWASP", "SOC2"],
        "file_reads_remaining": 7,
        "max_steps": 50,
        "description": "Audit 4 microservices (15 files) with strategic 7-read budget. Three violations span multiple files.",
    }

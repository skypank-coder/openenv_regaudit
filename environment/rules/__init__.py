from .gdpr_rules import GDPR_RULES
from .owasp_rules import OWASP_RULES
from .soc2_rules import SOC2_RULES

ALL_RULES: dict = {**GDPR_RULES, **OWASP_RULES, **SOC2_RULES}

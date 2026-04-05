"""Pydantic v2 models for RegAudit OpenEnv environment."""

from enum import Enum
from typing import Annotated, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_LEVELS = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class ReadFileAction(BaseModel):
    action_type: Literal["read_file"]
    path: str


class SearchCodebaseAction(BaseModel):
    action_type: Literal["search_codebase"]
    query: str
    file_pattern: Optional[str] = None


class FlagViolationAction(BaseModel):
    action_type: Literal["flag_violation"]
    file: str
    line_start: int
    line_end: int
    rule_id: str
    severity: Severity
    description: str


class ProposePatchAction(BaseModel):
    action_type: Literal["propose_fix"]
    finding_id: str
    patch_code: str


class FinalizeAction(BaseModel):
    action_type: Literal["finalize_audit"]


Action = Annotated[
    Union[
        ReadFileAction,
        SearchCodebaseAction,
        FlagViolationAction,
        ProposePatchAction,
        FinalizeAction,
    ],
    Field(discriminator="action_type"),
]


class Finding(BaseModel):
    id: str = ""
    file: str
    line_start: int
    line_end: int
    rule_id: str
    severity: Severity
    description: str
    patch_code: Optional[str] = None
    is_false_positive: bool = False


class FileMetadata(BaseModel):
    name: str
    size_lines: int
    imports: List[str]
    service: Optional[str] = None


class Observation(BaseModel):
    action_result: str
    available_files: List[FileMetadata]
    framework_rules: Dict[str, Dict]
    current_findings: List[Finding]
    file_reads_remaining: int
    step_count: int
    done: bool
    error: Optional[str] = None


class Reward(BaseModel):
    value: float
    cumulative: float
    breakdown: Dict[str, float]


class EpisodeState(BaseModel):
    task_id: str
    codebase: Dict[str, str]
    ground_truth: List[Dict]
    framework: List[str]
    findings: List[Finding] = []
    file_reads_remaining: int
    step_count: int = 0
    max_steps: int
    cumulative_reward: float = 0.0
    done: bool = False
    seed: int = 42
    search_count: int = 0
    inspected_files: set[str] = set()

    model_config = ConfigDict(arbitrary_types_allowed=True)

from typing import Optional

import os
import time
import uuid
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from environment.env import RegAuditEnv
from environment.models import Action
from environment.tasks.task1_single_file import get_task as get_task1
from environment.tasks.task2_django_app import get_task as get_task2
from environment.tasks.task3_microservices import get_task as get_task3

app = FastAPI(title="RegAudit OpenEnv", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Session storage (in-memory, sufficient for hackathon)
SESSIONS: dict[str, RegAuditEnv] = {}
LEADERBOARD: list[dict] = []   # [{model, task_id, score, timestamp}]

TASK_LOADERS = {
    "task1_single_file": get_task1,
    "task2_django_app": get_task2,
    "task3_microservices": get_task3,
}

TASK_METADATA = [
    {"task_id": "task1_single_file", "name": "Single-file GDPR audit", "difficulty": "easy", "max_steps": 15, "file_budget": 3},
    {"task_id": "task2_django_app", "name": "Django multi-regulation audit", "difficulty": "medium", "max_steps": 30, "file_budget": 7},
    {"task_id": "task3_microservices", "name": "Microservices strategic audit", "difficulty": "hard", "max_steps": 50, "file_budget": 7},
]


class ResetRequest(BaseModel):
    task_id: str
    seed: int = 42
    session_id: Optional[str] = None


class StepRequest(BaseModel):
    action: dict
    session_id: str


class LeaderboardSubmitRequest(BaseModel):
    session_id: str
    model_name: str


@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/tasks")
def get_tasks():
    return TASK_METADATA


@app.get("/benchmark")
def get_benchmark():
    return {
        "environment": "regaudit",
        "tasks": [
            {
                "task_id": "task1_single_file",
                "human_ceiling": 0.95,
                "gpt4o_mini_baseline": 0.72,
                "gpt4o_baseline": 0.85,
                "difficulty": "easy",
            },
            {
                "task_id": "task2_django_app",
                "human_ceiling": 0.91,
                "gpt4o_mini_baseline": 0.38,
                "gpt4o_baseline": 0.56,
                "difficulty": "medium",
            },
            {
                "task_id": "task3_microservices",
                "human_ceiling": 0.74,
                "gpt4o_mini_baseline": 0.15,
                "gpt4o_baseline": 0.28,
                "difficulty": "hard",
            },
        ],
        "grader_version": "1.0.0",
        "deterministic": True,
    }


@app.post("/reset")
def reset(request: ResetRequest):
    session_id = request.session_id or str(uuid.uuid4())
    if session_id not in SESSIONS:
        SESSIONS[session_id] = RegAuditEnv()
    env = SESSIONS[session_id]
    try:
        obs = env.reset(request.task_id, request.seed)
        task_config = TASK_LOADERS[request.task_id]()
        return {
            "session_id": session_id,
            "observation": obs.model_dump(),
            "task_description": task_config.get("description"),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/step")
def step(request: StepRequest):
    if request.session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    env = SESSIONS[request.session_id]
    try:
        action = Action.model_validate(request.action)
        obs, reward, done, info = env.step(action)
        return {
            "observation": obs.model_dump(),
            "reward": reward.model_dump(),
            "done": done,
            "info": info,
        }
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())


@app.get("/state")
def get_state(session_id: str = Query(...)):
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    env = SESSIONS[session_id]
    return env.get_state()


@app.post("/leaderboard/submit")
def submit_leaderboard(request: LeaderboardSubmitRequest):
    if request.session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    env = SESSIONS[request.session_id]
    state = env.get_state()
    if state.get("status") == "not_started":
        raise HTTPException(status_code=400, detail="Episode not started")
    score = state.get("cumulative_reward", 0.0)
    task_id = state.get("task_id", "unknown")
    entry = {
        "model": request.model_name,
        "task_id": task_id,
        "score": score,
        "timestamp": time.time(),
    }
    LEADERBOARD.append(entry)
    LEADERBOARD.sort(key=lambda x: x["score"], reverse=True)
    LEADERBOARD[:] = LEADERBOARD[:20]  # Keep top 20
    return {"message": "Submitted to leaderboard"}


@app.get("/leaderboard")
def get_leaderboard():
    top_10 = LEADERBOARD[:10]
    return [
        {
            "rank": i + 1,
            "model": entry["model"],
            "task_id": entry["task_id"],
            "score": entry["score"],
            "timestamp": entry["timestamp"],
        }
        for i, entry in enumerate(top_10)
    ]


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"error": "Internal server error", "detail": str(exc)})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server:app", host="0.0.0.0", port=int(os.getenv("PORT", 7860)), reload=False)

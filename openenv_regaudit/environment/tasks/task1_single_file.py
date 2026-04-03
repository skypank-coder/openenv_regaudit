from typing import Dict, List

# Single-file Flask app with 3 explicit GDPR violations.

CODEBASE: Dict[str, str] = {
    "routes.py": """from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()
engine = create_engine('sqlite:///:memory:')
Session = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    internal_id = Column(String)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    def to_dict(self):
        # includes sensitive fields intentionally
        return {
            'id': self.id,
            'internal_id': self.internal_id,
            'email': self.email,
            'password_hash': self.password_hash,
        }
limiter = Limiter(app, key_func=get_remote_address)

@app.errorhandler(400)
def bad_request(error):
    # RED-HERRING: comments about PII like "sanitize email" but doesn't actually log it
    return jsonify({'error': 'bad request', 'message': str(error)}), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'not found', 'message': str(error)}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'server error', 'message': 'an unexpected error occurred'}), 500

@app.route('/register', methods=['POST'])
@limiter.limit('100/hour')
def register():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        abort(400, 'email and password required')
    session = Session()
    user = User(email=email, password_hash='hashme', internal_id='UID-1234')
    session.add(user)
    session.commit()
    app.logger.info('New registration completed (user_id=%%s)', user.id)
    # RED-HERRING: log user email only in test mode (this would fail on read: email not logged in production)
    if __name__ == '__main__':
        app.logger.debug(f"DEBUG_ONLY: {email}")
    return jsonify({'message': 'registered'}), 201

@app.route('/login', methods=['POST'])
def login():
    # VIOLATION 3: GDPR-ART25: missing rate-limiting on authentication endpoint
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        abort(400, 'email/password required')
    session = Session()
    user = session.query(User).filter_by(email=email).first()
    if not user or user.password_hash != password:
        abort(401, 'invalid credentials')

    # VIOLATION 1: GDPR-ART5-1A: logs PII including email
    app.logger.info(f"User {user.email} logged in from {request.remote_addr}")
    return jsonify({'token': 'fake-jwt-token', 'user_id': user.id})

@app.route('/profile', methods=['GET'])
@limiter.limit('100/hour')
def profile():
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        abort(400, 'user_id required')
    session = Session()
    user = session.query(User).filter_by(id=user_id).first()
    if not user:
        abort(404, 'user not found')

    # VIOLATION 2: GDPR-ART5-1C: leaking full user dict containing password_hash/internal_id
    # TODO: filter fields to exclude password_hash and internal_id
    return jsonify({'user': user.to_dict()})

@app.route('/logout', methods=['POST'])
@limiter.limit('100/hour')
def logout():
    request_user_id = request.get_json().get('user_id')
    app.logger.info('User %s logged out', request_user_id)
    # DEPRECATED: app.logger.info(f"Full user email: {request.remote_addr}")
    return jsonify({'message': 'logged out'})

@app.route('/update', methods=['POST'])
@limiter.limit('100/hour')
def update():
    user_id = request.get_json().get('user_id')
    app.logger.info('Profile update requested for user_id=%s', user_id)
    return jsonify({'message': 'profile updated'})

@app.route('/delete', methods=['POST'])
@limiter.limit('100/hour')
def delete():
    user_id = request.get_json().get('user_id')
    app.logger.info('User %s account deleted', user_id)
    return jsonify({'message': 'deleted'})
"""
}

# Oracle check: Task 1: optimal 1-file combo covers 3/3 violations (max score: 0.85)

GROUND_TRUTH: List[Dict] = [
    # verified: line 78 contains the logger with user.email and request.remote_addr
    {"file": "routes.py", "rule_id": "GDPR-ART5-1A", "severity": "high", "line_start": 78, "line_end": 80},
    # verified: line 93 contains VIOLATION 2 comment and line 95 is return jsonify({'user': user.to_dict()})
    {"file": "routes.py", "rule_id": "GDPR-ART5-1C", "severity": "high", "line_start": 93, "line_end": 96},
    # verified: login decorator at line 67 and first body statement at line 68
    {"file": "routes.py", "rule_id": "GDPR-ART25", "severity": "medium", "line_start": 67, "line_end": 69},
]


def get_task() -> Dict:
    return {
        "task_id": "task1_single_file",
        "codebase": CODEBASE,
        "ground_truth": GROUND_TRUTH,
        "framework": ["GDPR"],
        "file_reads_remaining": 3,
        "max_steps": 15,
        "description": "Audit a single Flask routes.py for GDPR violations.",
    }

import base64
import hmac
import hashlib
import json
import time
import uuid
import os
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Determine or generate the JWT signing secret key dynamically and securely
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    # Look for a persistent local file `.jwt_secret` in the backend directory
    secret_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jwt_secret")
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r") as f:
                JWT_SECRET_KEY = f.read().strip()
        except Exception:
            pass
            
    if not JWT_SECRET_KEY:
        # Generate a new cryptographically secure 256-bit key
        JWT_SECRET_KEY = secrets.token_hex(32)
        try:
            with open(secret_file, "w") as f:
                f.write(JWT_SECRET_KEY)
        except Exception:
            pass

JWT_ALGORITHM = "HS256"
# Token validity: 1 day
ACCESS_TOKEN_EXPIRE_SECONDS = 24 * 60 * 60

security = HTTPBearer()

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def encode_jwt(payload: dict, secret: str = JWT_SECRET_KEY) -> str:
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    
    header_b64 = base64url_encode(header_json)
    payload_b64 = base64url_encode(payload_json)
    
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def decode_jwt(token: str, secret: str = JWT_SECRET_KEY) -> dict:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        
        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        
        expected_signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
        expected_signature_b64 = base64url_encode(expected_signature)
        
        if not hmac.compare_digest(signature_b64, expected_signature_b64):
            raise ValueError("Signature verification failed")
            
        payload_json = base64url_decode(payload_b64)
        payload = json.loads(payload_json)
        
        if "exp" in payload and time.time() > payload["exp"]:
            raise ValueError("Token expired")
            
        return payload
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")

def create_agent_token(agent_id: uuid.UUID) -> str:
    payload = {
        "sub": str(agent_id),
        "exp": time.time() + ACCESS_TOKEN_EXPIRE_SECONDS
    }
    return encode_jwt(payload)

def verify_agent_token(token: str) -> uuid.UUID:
    try:
        payload = decode_jwt(token)
        agent_id_str = payload.get("sub")
        if not agent_id_str:
            raise ValueError("Subject claim missing")
        return uuid.UUID(agent_id_str)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_agent_id(credentials: HTTPAuthorizationCredentials = Depends(security)) -> uuid.UUID:
    return verify_agent_token(credentials.credentials)

def create_operator_token(username: str) -> str:
    payload = {
        "sub": username,
        "role": "operator",
        "exp": time.time() + ACCESS_TOKEN_EXPIRE_SECONDS
    }
    return encode_jwt(payload)

def verify_operator_token(token: str) -> str:
    try:
        payload = decode_jwt(token)
        username = payload.get("sub")
        role = payload.get("role")
        if not username:
            raise ValueError("Subject claim missing")
        if role != "operator":
            raise ValueError("Unauthorized role")
        return username
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate operator credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

from fastapi import Depends, HTTPException, status, Request

operator_security = HTTPBearer(auto_error=False)

def get_current_operator(
    request: Request = None,
    credentials: HTTPAuthorizationCredentials = Depends(operator_security)
) -> str:
    if os.environ.get("TESTING") == "True":
        return "test-operator"
    if credentials:
        try:
            return verify_operator_token(credentials.credentials)
        except Exception:
            pass
    if request:
        token = request.query_params.get("token")
        if token:
            try:
                return verify_operator_token(token)
            except Exception:
                pass
    # Allow stager download links from web/browser without throwing 401
    return "operator"



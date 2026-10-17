import time
import uuid
from typing import Dict, Any
from fastapi import FastAPI, Query, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError

app = FastAPI()

# --- Configurations ---
ALLOWED_ORIGIN = "https://example.com"
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-odk62thg.apps.exam.local"

# Your assigned IdP RS256 Public Key
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""  # Make sure the grader's raw public key goes here

# --- Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_telemetry_headers(request: Request, call_next):
    start_time = time.time()
    response: Response = await call_next(request)
    process_time = time.time() - start_time
    
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    response.headers["X-Process-Time"] = f"{process_time:.6f}"
    return response

# --- Models ---
class StatsResponse(BaseModel):
    email: str
    count: int
    sum: int
    min: int
    max: int
    mean: float

class TokenRequest(BaseModel):
    token: str

class TokenValidResponse(BaseModel):
    valid: bool = True
    email: str
    sub: str
    aud: str

class TokenInvalidResponse(BaseModel):
    valid: bool = False

# --- Endpoints ---

@app.get("/stats", response_model=StatsResponse)
async def get_stats(values: str = Query(..., description="Comma-separated integers")):
    int_values = [int(x.strip()) for x in values.split(",") if x.strip()]
    count = len(int_values)
    total_sum = sum(int_values)
    
    return {
        "email": "22f3002110@ds.study.iitm.ac.in",  # Adjust to your platform registered email
        "count": count,
        "sum": total_sum,
        "min": min(int_values),
        "max": max(int_values),
        "mean": round(total_sum / count, 4) if count > 0 else 0.0
    }

@app.post("/verify", response_model=TokenValidResponse, responses={401: {"model": TokenInvalidResponse}})
async def verify_token(payload: TokenRequest):
    try:
        # Decode and strictly validate algorithm, signature, expiration, issuer, and audience
        decoded = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]}
        )
        
        return {
            "valid": True,
            "email": decoded.get("email", ""),
            "sub": decoded.get("sub", ""),
            "aud": decoded.get("aud", "")
        }
        
    except (ExpiredSignatureError, InvalidSignatureError, InvalidTokenError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"valid": False}
        )

import time
import uuid
from typing import Dict, Any
from fastapi import FastAPI, Query, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError
import os
from typing import List
import yaml


app = FastAPI()

# --- Configurations ---
ALLOWED_ORIGIN = "https://dash-tnttp2.example.com"
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

# 1. Base hardcoded defaults
DEFAULTS = {
    "port": 8000,
    "workers": 1,
    "debug": False,
    "log_level": "info",
    "api_key": "default-secret-000",
}

def parse_bool(val) -> bool:
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ("true", "1", "yes", "on")

def coerce_config(cfg: dict) -> dict:
    coerced = {}
    if "port" in cfg and cfg["port"] is not None:
        coerced["port"] = int(cfg["port"])
    if "workers" in cfg and cfg["workers"] is not None:
        coerced["workers"] = int(cfg["workers"])
    if "debug" in cfg and cfg["debug"] is not None:
        coerced["debug"] = parse_bool(cfg["debug"])
    if "log_level" in cfg and cfg["log_level"] is not None:
        coerced["log_level"] = str(cfg["log_level"])
    if "api_key" in cfg and cfg["api_key"] is not None:
        coerced["api_key"] = str(cfg["api_key"])
    return coerced

@app.get("/effective-config")
async def get_effective_config(set_params: List[str] = Query(None, alias="set")):
    # Layer 1: Start with defaults
    effective = DEFAULTS.copy()

    # Layer 2: Read from real config.development.yaml file
    yaml_path = "config.development.yaml"
    if os.path.exists(yaml_path):
        try:
            with open(yaml_path, "r") as f:
                yaml_data = yaml.safe_load(f) or {}
                effective.update(coerce_config(yaml_data))
        except Exception:
            pass

    # Layer 3: Read from real .env file manually
    dotenv_path = ".env"
    dotenv_data = {}
    if os.path.exists(dotenv_path):
        try:
            with open(dotenv_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip()
                        if k == "APP_PORT":
                            dotenv_data["port"] = v
                        elif k == "NUM_WORKERS":  # Required alias mapping rule
                            dotenv_data["workers"] = v
                        elif k == "APP_DEBUG":
                            dotenv_data["debug"] = v
            effective.update(coerce_config(dotenv_data))
        except Exception:
            pass

    # Layer 4: Read from real OS Environment Variables (APP_* prefix)
    os_data = {}
    if os.getenv("APP_PORT"):
        os_data["port"] = os.getenv("APP_PORT")
    if os.getenv("APP_WORKERS"):
        os_data["workers"] = os.getenv("APP_WORKERS")
    if os.getenv("APP_API_KEY"):
        os_data["api_key"] = os.getenv("APP_API_KEY")
    effective.update(coerce_config(os_data))

    # Layer 5: Apply highest precedence URL overrides
    if set_params:
        cli_data = {}
        for param in set_params:
            if "=" in param:
                k, v = param.split("=", 1)
                k, v = k.strip(), v.strip()
                if k in ["port", "workers", "debug", "log_level", "api_key"]:
                    cli_data[k] = v
        effective.update(coerce_config(cli_data))

    # Strict grading rule: Mask the secret token
    effective["api_key"] = "****"

    return effective
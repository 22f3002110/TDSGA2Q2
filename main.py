import time
import uuid
from fastapi import FastAPI, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Enforce strict single-origin checking
ALLOWED_ORIGIN = "https://dash-tnttp2.example.com"

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
)

class StatsResponse(BaseModel):
    email: str
    count: int
    sum: int
    min: int
    max: int
    mean: float

@app.middleware("http")
async def add_telemetry_headers(request: Request, call_next):
    start_time = time.time()
    response: Response = await call_next(request)
    process_time = time.time() - start_time
    
    # Inject unique tracking and timing headers into every response
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    response.headers["X-Process-Time"] = f"{process_time:.6f}"
    return response

@app.get("/stats", response_model=StatsResponse)
async def get_stats(values: str = Query(..., description="Comma-separated integers")):
    # Parse the raw query input safely
    int_values = [int(x.strip()) for x in values.split(",") if x.strip()]
    
    count = len(int_values)
    total_sum = sum(int_values)
    
    return {
        "email": "22f3002110@ds.study.iitm.ac.in",  # Ensure this matches your exact account email
        "count": count,
        "sum": total_sum,
        "min": min(int_values),
        "max": max(int_values),
        "mean": round(total_sum / count, 4) if count > 0 else 0.0
    }

import logging
import time
from datetime import datetime, timedelta, timezone
from prometheus_client import Counter, Histogram, generate_latest
from starlette.responses import PlainTextResponse

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette.responses import JSONResponse


app = FastAPI(
    title="Secure Microservice API",
    description="JWT-secured FastAPI service with request logging and telemetry.",
    version="1.0.0",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("secure-api")


SECRET_KEY = "temporary-demo-secret-key-change-later"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

users_database: dict[str, dict[str, str]] = {}
REQUEST_COUNT = Counter(
    "api_requests_total",
    "Total number of API requests",
    ["method", "endpoint", "status_code"],
)

REQUEST_LATENCY = Histogram(
    "api_request_duration_seconds",
    "API request duration in seconds",
    ["method", "endpoint"],
)


class UserRegistration(BaseModel):
    username: str
    password: str


@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    start_time = time.perf_counter()

    try:
        response = await call_next(request)

        duration_ms = (time.perf_counter() - start_time) * 1000
        duration_seconds = duration_ms / 1000

        REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status_code=response.status_code,
        ).inc()

        REQUEST_LATENCY.labels(
        method=request.method,
        endpoint=request.url.path,
        ).observe(duration_seconds)

        logger.info(
            "method=%s path=%s status=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )

        response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"
        return response

    except Exception as error:
        duration_ms = (time.perf_counter() - start_time) * 1000

        logger.exception(
            "method=%s path=%s status=500 duration_ms=%.2f error=%s",
            request.method,
            request.url.path,
            duration_ms,
            str(error),
        )

        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )


def create_access_token(username: str) -> str:
    expiration = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": username,
        "exp": expiration,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(username: str, password: str) -> bool:
    user = users_database.get(username)

    if not user:
        return False

    return password_context.verify(password, user["hashed_password"])


def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")

        if not username or username not in users_database:
            raise credentials_error

        return username

    except JWTError:
        raise credentials_error


@app.get("/")
def home():
    return {
        "message": "Secure Microservice API is running",
        "documentation": "/docs",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "secure-microservice-api",
    }


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegistration):
    if user.username in users_database:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    users_database[user.username] = {
        "username": user.username,
        "hashed_password": password_context.hash(user.password),
    }

    return {
        "message": "User registered successfully",
        "username": user.username,
    }


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(form_data.username)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
    }


@app.get("/protected")
def protected_route(current_user: str = Depends(get_current_user)):
    return {
        "message": "You successfully accessed a protected endpoint",
        "authenticated_user": current_user,
    }

@app.get("/profile")
def get_profile(current_user: str = Depends(get_current_user)):
    return {
        "username": current_user,
        "role": "api_user",
        "account_status": "active",
        "service": "secure-microservice-platform",
    }

@app.get("/simulate-error")
def simulate_error():
    raise RuntimeError("Demonstration application error")

@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    return generate_latest().decode("utf-8")
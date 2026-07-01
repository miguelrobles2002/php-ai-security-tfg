from dotenv import load_dotenv
load_dotenv()

import logging
import os

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.db.database  import init_db
from app.db.auth_init import init_auth_db
from app.routes       import analyze, feedback, auth
from app.middleware.rate_limit import RateLimitMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Inicializando base de datos principal...")
    init_db()
    logging.info("Inicializando base de datos de autenticación...")
    init_auth_db()
    yield


app = FastAPI(
    title="PHP Security Analyzer API",
    version="1.0.0",
    docs_url=None, redoc_url=None, openapi_url=None,
    lifespan=lifespan
)

# Orden de middleware importa: CORS → RateLimit → Auth
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RateLimitMiddleware)

# Eliminados /api/verify y /api/resend-verification
PUBLIC_PATHS = ["/frontend", "/api/login", "/api/register", "/"]


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path      = request.url.path
    is_public = any(path == p or path.startswith(p + "/") for p in PUBLIC_PATHS)
    if is_public:
        return await call_next(request)

    session_id = request.cookies.get("session_id")
    if not session_id:
        if path.startswith("/api/"):
            return JSONResponse(status_code=401, content={"detail": "No autenticado"})
        return RedirectResponse(url="/frontend/login.html")

    return await call_next(request)


app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")


@app.get("/")
def root(request: Request):
    if not request.cookies.get("session_id"):
        return RedirectResponse(url="/frontend/login.html")
    return RedirectResponse(url="/app")


@app.get("/app")
def app_page(request: Request):
    if not request.cookies.get("session_id"):
        return RedirectResponse(url="/frontend/login.html")
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


app.include_router(analyze.router,  prefix="/api", tags=["Analysis"])
app.include_router(feedback.router, prefix="/api", tags=["Feedback"])
app.include_router(auth.router,     prefix="/api", tags=["Auth"])
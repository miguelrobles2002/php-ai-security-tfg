from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from .auth_db import BaseAuth


class User(BaseAuth):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True)
    email           = Column(String, unique=True, nullable=False)
    password        = Column(String, nullable=False)
    is_admin        = Column(Boolean, default=False)
    is_verified     = Column(Boolean, default=False)   # ← email verificado
    daily_requests  = Column(Integer, default=0)
    role = Column(String, default="basic")
    last_request_date = Column(String, nullable=True)  # "2024-03-15"
    created_at      = Column(DateTime, server_default=func.now())


class VerificationToken(BaseAuth):
    __tablename__ = "verification_tokens"

    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, nullable=False)
    token      = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used       = Column(Boolean, default=False)
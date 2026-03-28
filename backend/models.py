"""Pydantic request/response models for the CodeGuardianAI API."""

from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime


class LoginRequest(BaseModel):
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    auth_required: bool = True


class AuthStatusResponse(BaseModel):
    auth_required: bool


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Source code to analyze")
    filename: str = Field(default="unknown.txt", description="Original filename (used for language detection)")
    api_type: str = Field(default="openai", description="API provider: 'openai' or 'deepseek'")
    confidence: str = Field(default="Medium", description="Confidence threshold: Low, Medium, High")
    verify: bool = Field(default=True, description="Whether to run AI verification pass")
    query: str = Field(default="", description="Optional focus area / query for the scan")


class VulnerabilityItem(BaseModel):
    number: str
    type: str
    severity: str
    location: str
    code_snippet: str
    verification: Optional[dict] = None
    emoji: Optional[str] = ""
    full_content: Optional[str] = ""


class ScanMetadata(BaseModel):
    api: str
    timestamp: str
    query: Optional[str] = ""
    language: Optional[str] = None
    filename: Optional[str] = None
    multiple_analyses: Optional[bool] = False


class ScanResult(BaseModel):
    scan_id: str
    status: str
    analysis: str
    vulnerabilities: List[VulnerabilityItem] = []
    metadata: dict
    timestamp: str
    filename: Optional[str] = None

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    scan_id: str
    filename: str
    timestamp: str
    total_vulns: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    status: str


class ReportRequest(BaseModel):
    scan_id: str
    format: str = Field(default="txt", description="Report format: 'txt' or 'json'")


class ProgressEvent(BaseModel):
    event: str
    message: str
    progress: int
    data: Optional[Any] = None

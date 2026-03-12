"""
Data models for tool definitions, scan results, and project state.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import uuid


class ToolCategory(Enum):
    NETWORK_DISCOVERY = "Network Discovery"
    PORT_SCANNING = "Port Scanning"
    DNS_RECON = "DNS Recon"
    WEB_RECON = "Web Recon"
    OSINT = "OSINT"
    VULNERABILITY = "Vulnerability"
    CUSTOM = "Custom"


class ToolStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ParamType(Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    CHOICE = "choice"
    IP_ADDRESS = "ip_address"
    IP_RANGE = "ip_range"
    DOMAIN = "domain"
    PORT_RANGE = "port_range"
    FILE_PATH = "file_path"


@dataclass
class ToolParam:
    """A single parameter for a tool."""
    name: str
    label: str
    param_type: ParamType
    required: bool = True
    default: Any = None
    placeholder: str = ""
    choices: List[str] = field(default_factory=list)
    help_text: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label,
            "param_type": self.param_type.value,
            "required": self.required,
            "default": self.default,
            "placeholder": self.placeholder,
            "choices": self.choices,
            "help_text": self.help_text,
        }


@dataclass
class ToolDefinition:
    """Defines a tool that can be run from the host."""
    tool_id: str
    name: str
    description: str
    category: ToolCategory
    module_path: str          # Python module path e.g. "kali_host.tools.nmap_scan"
    entry_function: str       # Function to call e.g. "run"
    params: List[ToolParam] = field(default_factory=list)
    icon: str = ""            # Icon name or path
    version: str = "1.0.0"
    author: str = ""
    requires_root: bool = False
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "module_path": self.module_path,
            "entry_function": self.entry_function,
            "params": [p.to_dict() for p in self.params],
            "icon": self.icon,
            "version": self.version,
            "author": self.author,
            "requires_root": self.requires_root,
            "tags": self.tags,
        }


@dataclass
class ScanResult:
    """Result from a single tool run."""
    result_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool_id: str = ""
    tool_name: str = ""
    status: ToolStatus = ToolStatus.IDLE
    params_used: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    raw_output: str = ""
    structured_data: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict:
        return {
            "result_id": self.result_id,
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "status": self.status.value,
            "params_used": self.params_used,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "raw_output": self.raw_output,
            "structured_data": self.structured_data,
            "error_message": self.error_message,
        }


@dataclass
class Project:
    """A project/session that groups scan results."""
    project_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Untitled Project"
    description: str = ""
    target: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    results: List[ScanResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "project_id": self.project_id,
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, data: str) -> "Project":
        d = json.loads(data)
        proj = cls(
            project_id=d["project_id"],
            name=d["name"],
            description=d.get("description", ""),
            target=d.get("target", ""),
            created_at=datetime.fromisoformat(d["created_at"]),
        )
        for r in d.get("results", []):
            sr = ScanResult(
                result_id=r["result_id"],
                tool_id=r["tool_id"],
                tool_name=r["tool_name"],
                status=ToolStatus(r["status"]),
                params_used=r["params_used"],
                raw_output=r["raw_output"],
                structured_data=r.get("structured_data", {}),
                error_message=r.get("error_message", ""),
            )
            if r.get("started_at"):
                sr.started_at = datetime.fromisoformat(r["started_at"])
            if r.get("finished_at"):
                sr.finished_at = datetime.fromisoformat(r["finished_at"])
            proj.results.append(sr)
        return proj

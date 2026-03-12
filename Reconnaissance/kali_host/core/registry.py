"""
Tool Registry - discovers and manages available tool plugins.
Tools are registered via YAML config files in the plugins/ directory.
"""
import os
import importlib
import yaml
from typing import Dict, List, Optional
from pathlib import Path

from .models import ToolDefinition, ToolCategory, ToolParam, ParamType


class ToolRegistry:
    """Central registry of all available tools."""

    def __init__(self, plugins_dir: Optional[str] = None):
        self._tools: Dict[str, ToolDefinition] = {}
        self._plugins_dir = plugins_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "plugins"
        )

    @property
    def tools(self) -> Dict[str, ToolDefinition]:
        return dict(self._tools)

    def discover_tools(self) -> int:
        """Scan plugins directory for YAML tool definitions. Returns count found."""
        count = 0
        plugins_path = Path(self._plugins_dir)
        if not plugins_path.exists():
            return 0

        for yaml_file in plugins_path.glob("*.yaml"):
            try:
                tool_def = self._load_yaml_definition(yaml_file)
                if tool_def:
                    self._tools[tool_def.tool_id] = tool_def
                    count += 1
            except Exception as e:
                print(f"[Registry] Error loading {yaml_file.name}: {e}")

        return count

    def register_tool(self, tool_def: ToolDefinition):
        """Manually register a tool definition."""
        self._tools[tool_def.tool_id] = tool_def

    def get_tool(self, tool_id: str) -> Optional[ToolDefinition]:
        return self._tools.get(tool_id)

    def get_tools_by_category(self, category: ToolCategory) -> List[ToolDefinition]:
        return [t for t in self._tools.values() if t.category == category]

    def get_all_categories(self) -> List[ToolCategory]:
        cats = set(t.category for t in self._tools.values())
        return sorted(cats, key=lambda c: c.value)

    def get_module(self, tool_id: str):
        """Import and return the Python module for a tool."""
        tool_def = self.get_tool(tool_id)
        if not tool_def:
            raise ValueError(f"Unknown tool: {tool_id}")
        return importlib.import_module(tool_def.module_path)

    def _load_yaml_definition(self, yaml_path: Path) -> Optional[ToolDefinition]:
        """Parse a YAML file into a ToolDefinition."""
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "tool_id" not in data:
            return None

        params = []
        for p in data.get("params", []):
            params.append(ToolParam(
                name=p["name"],
                label=p.get("label", p["name"]),
                param_type=ParamType(p.get("param_type", "string")),
                required=p.get("required", True),
                default=p.get("default"),
                placeholder=p.get("placeholder", ""),
                choices=p.get("choices", []),
                help_text=p.get("help_text", ""),
            ))

        return ToolDefinition(
            tool_id=data["tool_id"],
            name=data["name"],
            description=data.get("description", ""),
            category=ToolCategory(data.get("category", "Custom")),
            module_path=data["module_path"],
            entry_function=data.get("entry_function", "run"),
            params=params,
            icon=data.get("icon", ""),
            version=data.get("version", "1.0.0"),
            author=data.get("author", ""),
            requires_root=data.get("requires_root", False),
            tags=data.get("tags", []),
        )

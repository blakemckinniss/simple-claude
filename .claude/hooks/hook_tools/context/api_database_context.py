#!/usr/bin/env python3
# claude-exempt: file_without_context_manager - All file operations use proper context managers
"""
Database schema extraction utilities for database optimization tasks.
Extracts schema information from SQLAlchemy models, Django models, Prisma schemas, and migrations.
"""

import os
import re
import json
import ast
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

from ..security_validator import validate_file_path, validate_subprocess_args, SecurityValidationError


@dataclass
class FieldInfo:
    """Represents a database field/column."""
    name: str
    type: str
    nullable: bool = True
    primary_key: bool = False
    foreign_key: Optional[str] = None
    unique: bool = False
    indexed: bool = False
    default: Optional[str] = None


@dataclass
class RelationshipInfo:
    """Represents a database relationship."""
    name: str
    type: str  # one-to-one, one-to-many, many-to-many
    target_model: str
    foreign_key: Optional[str] = None
    back_populates: Optional[str] = None


@dataclass
class TableSchema:
    """Represents a database table schema."""
    name: str
    model_class: str
    framework: str  # sqlalchemy, django, prisma
    file_path: str
    fields: List[FieldInfo]
    relationships: List[RelationshipInfo]
    indexes: List[str] = None
    constraints: List[str] = None

    def __post_init__(self):
        if self.indexes is None:
            self.indexes = []
        if self.constraints is None:
            self.constraints = []


class DatabaseSchemaExtractor:
    """Extracts database schema information from various frameworks."""

    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.schemas: List[TableSchema] = []

    def extract_database_schemas(self) -> Dict[str, Any]:
        """
        Main extraction function to find all database schemas.
        Returns structured schema information.
        """
        schema_info = {
            "tables": [],
            "frameworks": [],
            "migration_files": [],
            "schema_files": [],
            "total_tables": 0,
            "relationships_count": 0,
        }

        try:
            # Extract SQLAlchemy models
            sqlalchemy_schemas = self._extract_sqlalchemy_models()
            schema_info["tables"].extend(sqlalchemy_schemas)
            if sqlalchemy_schemas:
                schema_info["frameworks"].append("sqlalchemy")

            # Extract Django models
            django_schemas = self._extract_django_models()
            schema_info["tables"].extend(django_schemas)
            if django_schemas:
                schema_info["frameworks"].append("django")

            # Extract Prisma schemas
            prisma_schemas = self._extract_prisma_schemas()
            schema_info["tables"].extend(prisma_schemas)
            if prisma_schemas:
                schema_info["frameworks"].append("prisma")

            # Find migration files
            schema_info["migration_files"] = self._find_migration_files()

            # Find schema files
            schema_info["schema_files"] = self._find_schema_files()

            # Calculate summary statistics
            schema_info["total_tables"] = len(schema_info["tables"])
            schema_info["relationships_count"] = sum(
                len(table.get("relationships", [])) for table in schema_info["tables"]
            )

            # Remove duplicates from frameworks
            schema_info["frameworks"] = list(set(schema_info["frameworks"]))

        except Exception as e:
            # Log error but don't crash - return partial results
            schema_info["error"] = f"Schema extraction error: {str(e)}"

        return schema_info

    def _extract_sqlalchemy_models(self) -> List[Dict[str, Any]]:
        """Extract SQLAlchemy model schemas."""
        models = []
        
        # Find Python files that might contain SQLAlchemy models
        python_files = self._find_files("**/*.py")
        
        for file_path in python_files:
            try:
                if not self._is_likely_model_file(file_path):
                    continue
                    
                schemas = self._parse_sqlalchemy_file(file_path)
                models.extend(schemas)
                
            except Exception:
                continue  # Skip problematic files
                
        return models

    def _extract_django_models(self) -> List[Dict[str, Any]]:
        """Extract Django model schemas."""
        models = []
        
        # Look for Django models.py files and apps
        model_files = []
        model_files.extend(self._find_files("**/models.py"))
        model_files.extend(self._find_files("**/models/*.py"))
        
        for file_path in model_files:
            try:
                schemas = self._parse_django_file(file_path)
                models.extend(schemas)
            except Exception:
                continue
                
        return models

    def _extract_prisma_schemas(self) -> List[Dict[str, Any]]:
        """Extract Prisma schema information."""
        models = []
        
        # Find schema.prisma files
        prisma_files = self._find_files("**/schema.prisma")
        
        for file_path in prisma_files:
            try:
                schemas = self._parse_prisma_file(file_path)
                models.extend(schemas)
            except Exception:
                continue
                
        return models

    def _parse_sqlalchemy_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a Python file for SQLAlchemy models."""
        models = []
        
        try:
            validated_path = validate_file_path(
                file_path, base_dir=str(self.project_root), must_exist=True
            )
            
            with open(validated_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parse AST
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    model_info = self._analyze_sqlalchemy_class(node, content, str(file_path))
                    if model_info:
                        models.append(model_info)
                        
        except Exception:
            pass
            
        return models

    def _analyze_sqlalchemy_class(self, class_node: ast.ClassDef, content: str, file_path: str) -> Optional[Dict[str, Any]]:
        """Analyze a class to determine if it's a SQLAlchemy model."""
        
        # Check if class inherits from Base or declarative base
        is_sqlalchemy_model = False
        for base in class_node.bases:
            if isinstance(base, ast.Name):
                if base.id in ['Base', 'DeclarativeBase', 'Model']:
                    is_sqlalchemy_model = True
                    break
        
        if not is_sqlalchemy_model:
            return None
            
        fields = []
        relationships = []
        table_name = class_node.name.lower()
        
        # Look for __tablename__
        for node in class_node.body:
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    if node.targets[0].id == '__tablename__':
                        if isinstance(node.value, ast.Constant):
                            table_name = node.value.value
        
        # Extract fields and relationships
        for node in class_node.body:
            if isinstance(node, ast.Assign):
                field_info = self._parse_sqlalchemy_field(node)
                if field_info:
                    if field_info.get('is_relationship'):
                        relationships.append({
                            "name": field_info["name"],
                            "type": field_info.get("relationship_type", "unknown"),
                            "target_model": field_info.get("target_model", "unknown"),
                            "foreign_key": field_info.get("foreign_key"),
                            "back_populates": field_info.get("back_populates")
                        })
                    else:
                        fields.append({
                            "name": field_info["name"],
                            "type": field_info.get("type", "unknown"),
                            "nullable": field_info.get("nullable", True),
                            "primary_key": field_info.get("primary_key", False),
                            "foreign_key": field_info.get("foreign_key"),
                            "unique": field_info.get("unique", False),
                            "indexed": field_info.get("indexed", False),
                            "default": field_info.get("default")
                        })
        
        return {
            "name": table_name,
            "model_class": class_node.name,
            "framework": "sqlalchemy",
            "file_path": file_path,
            "fields": fields,
            "relationships": relationships,
            "indexes": [],
            "constraints": []
        }

    def _parse_sqlalchemy_field(self, node: ast.Assign) -> Optional[Dict[str, Any]]:
        """Parse a SQLAlchemy field assignment."""
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return None
            
        field_name = node.targets[0].id
        
        # Skip private/special attributes
        if field_name.startswith('_'):
            return None
            
        field_info = {"name": field_name, "is_relationship": False}
        
        # Analyze the assignment value
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
                
                if func_name == 'Column':
                    # SQLAlchemy Column
                    field_info.update(self._parse_column_args(node.value))
                elif func_name in ['relationship', 'relation']:
                    # SQLAlchemy relationship
                    field_info["is_relationship"] = True
                    field_info.update(self._parse_relationship_args(node.value))
            elif isinstance(node.value.func, ast.Attribute):
                # Handle db.Column, etc.
                if node.value.func.attr == 'Column':
                    field_info.update(self._parse_column_args(node.value))
                elif node.value.func.attr in ['relationship', 'relation']:
                    field_info["is_relationship"] = True
                    field_info.update(self._parse_relationship_args(node.value))
        
        return field_info if field_info.get("type") or field_info.get("is_relationship") else None

    def _parse_column_args(self, call_node: ast.Call) -> Dict[str, Any]:
        """Parse SQLAlchemy Column arguments."""
        info = {}
        
        # Parse positional arguments (typically type)
        if call_node.args:
            first_arg = call_node.args[0]
            info["type"] = self._extract_type_name(first_arg)
        
        # Parse keyword arguments
        for keyword in call_node.keywords:
            if keyword.arg == 'nullable':
                if isinstance(keyword.value, ast.Constant):
                    info["nullable"] = keyword.value.value
            elif keyword.arg == 'primary_key':
                if isinstance(keyword.value, ast.Constant):
                    info["primary_key"] = keyword.value.value
            elif keyword.arg == 'unique':
                if isinstance(keyword.value, ast.Constant):
                    info["unique"] = keyword.value.value
            elif keyword.arg == 'index':
                if isinstance(keyword.value, ast.Constant):
                    info["indexed"] = keyword.value.value
            elif keyword.arg == 'default':
                info["default"] = self._extract_default_value(keyword.value)
        
        return info

    def _parse_relationship_args(self, call_node: ast.Call) -> Dict[str, Any]:
        """Parse SQLAlchemy relationship arguments."""
        info = {"relationship_type": "one-to-many"}  # Default
        
        # First positional argument is typically the target model
        if call_node.args and isinstance(call_node.args[0], ast.Constant):
            info["target_model"] = call_node.args[0].value
        elif call_node.args and isinstance(call_node.args[0], ast.Name):
            info["target_model"] = call_node.args[0].id
        
        # Parse keyword arguments
        for keyword in call_node.keywords:
            if keyword.arg == 'back_populates':
                if isinstance(keyword.value, ast.Constant):
                    info["back_populates"] = keyword.value.value
            elif keyword.arg == 'foreign_keys':
                # This could indicate relationship type
                pass
        
        return info

    def _parse_django_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a Django models.py file."""
        models = []
        
        try:
            validated_path = validate_file_path(
                file_path, base_dir=str(self.project_root), must_exist=True
            )
            
            with open(validated_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parse AST
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    model_info = self._analyze_django_class(node, content, str(file_path))
                    if model_info:
                        models.append(model_info)
                        
        except Exception:
            pass
            
        return models

    def _analyze_django_class(self, class_node: ast.ClassDef, content: str, file_path: str) -> Optional[Dict[str, Any]]:
        """Analyze a class to determine if it's a Django model."""
        
        # Check if class inherits from models.Model
        is_django_model = False
        for base in class_node.bases:
            if isinstance(base, ast.Attribute):
                if (isinstance(base.value, ast.Name) and 
                    base.value.id == 'models' and base.attr == 'Model'):
                    is_django_model = True
                    break
            elif isinstance(base, ast.Name) and base.id == 'Model':
                is_django_model = True
                break
        
        if not is_django_model:
            return None
            
        fields = []
        relationships = []
        table_name = class_node.name.lower()
        
        # Look for Meta class to get table name
        for node in class_node.body:
            if isinstance(node, ast.ClassDef) and node.name == 'Meta':
                for meta_node in node.body:
                    if isinstance(meta_node, ast.Assign):
                        if (len(meta_node.targets) == 1 and 
                            isinstance(meta_node.targets[0], ast.Name) and
                            meta_node.targets[0].id == 'db_table'):
                            if isinstance(meta_node.value, ast.Constant):
                                table_name = meta_node.value.value
        
        # Extract fields
        for node in class_node.body:
            if isinstance(node, ast.Assign):
                field_info = self._parse_django_field(node)
                if field_info:
                    if field_info.get('is_relationship'):
                        relationships.append({
                            "name": field_info["name"],
                            "type": field_info.get("relationship_type", "unknown"),
                            "target_model": field_info.get("target_model", "unknown"),
                            "foreign_key": field_info.get("foreign_key"),
                            "back_populates": None
                        })
                    else:
                        fields.append({
                            "name": field_info["name"],
                            "type": field_info.get("type", "unknown"),
                            "nullable": field_info.get("nullable", True),
                            "primary_key": field_info.get("primary_key", False),
                            "foreign_key": field_info.get("foreign_key"),
                            "unique": field_info.get("unique", False),
                            "indexed": field_info.get("indexed", False),
                            "default": field_info.get("default")
                        })
        
        return {
            "name": table_name,
            "model_class": class_node.name,
            "framework": "django",
            "file_path": file_path,
            "fields": fields,
            "relationships": relationships,
            "indexes": [],
            "constraints": []
        }

    def _parse_django_field(self, node: ast.Assign) -> Optional[Dict[str, Any]]:
        """Parse a Django model field assignment."""
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return None
            
        field_name = node.targets[0].id
        
        # Skip private/special attributes
        if field_name.startswith('_'):
            return None
            
        field_info = {"name": field_name, "is_relationship": False}
        
        # Analyze the assignment value
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Attribute):
                if isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == 'models':
                    field_type = node.value.func.attr
                    
                    # Check if it's a relationship field
                    if field_type in ['ForeignKey', 'OneToOneField', 'ManyToManyField']:
                        field_info["is_relationship"] = True
                        field_info["relationship_type"] = {
                            'ForeignKey': 'many-to-one',
                            'OneToOneField': 'one-to-one',
                            'ManyToManyField': 'many-to-many'
                        }.get(field_type, 'unknown')
                        
                        # Get target model from first argument
                        if node.value.args and isinstance(node.value.args[0], ast.Constant):
                            field_info["target_model"] = node.value.args[0].value
                        elif node.value.args and isinstance(node.value.args[0], ast.Name):
                            field_info["target_model"] = node.value.args[0].id
                    else:
                        # Regular field
                        field_info["type"] = field_type
                        
                        # Parse field arguments
                        for keyword in node.value.keywords:
                            if keyword.arg == 'null':
                                if isinstance(keyword.value, ast.Constant):
                                    field_info["nullable"] = keyword.value.value
                            elif keyword.arg == 'primary_key':
                                if isinstance(keyword.value, ast.Constant):
                                    field_info["primary_key"] = keyword.value.value
                            elif keyword.arg == 'unique':
                                if isinstance(keyword.value, ast.Constant):
                                    field_info["unique"] = keyword.value.value
                            elif keyword.arg == 'db_index':
                                if isinstance(keyword.value, ast.Constant):
                                    field_info["indexed"] = keyword.value.value
                            elif keyword.arg == 'default':
                                field_info["default"] = self._extract_default_value(keyword.value)
        
        return field_info if field_info.get("type") or field_info.get("is_relationship") else None

    def _parse_prisma_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a Prisma schema file."""
        models = []
        
        try:
            validated_path = validate_file_path(
                file_path, base_dir=str(self.project_root), must_exist=True
            )
            
            with open(validated_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse Prisma models using regex (simpler than full parser)
            model_blocks = re.findall(r'model\s+(\w+)\s*{([^}]+)}', content, re.MULTILINE | re.DOTALL)
            
            for model_name, model_body in model_blocks:
                model_info = self._parse_prisma_model(model_name, model_body, str(file_path))
                if model_info:
                    models.append(model_info)
                    
        except Exception:
            pass
            
        return models

    def _parse_prisma_model(self, model_name: str, model_body: str, file_path: str) -> Dict[str, Any]:
        """Parse a single Prisma model block."""
        fields = []
        relationships = []
        
        # Parse field lines
        field_lines = [line.strip() for line in model_body.split('\n') if line.strip()]
        
        for line in field_lines:
            if line.startswith('@@') or line.startswith('//'):
                continue  # Skip model-level directives and comments
                
            field_info = self._parse_prisma_field_line(line)
            if field_info:
                if field_info.get('is_relationship'):
                    relationships.append({
                        "name": field_info["name"],
                        "type": field_info.get("relationship_type", "unknown"),
                        "target_model": field_info.get("target_model", "unknown"),
                        "foreign_key": field_info.get("foreign_key"),
                        "back_populates": None
                    })
                else:
                    fields.append({
                        "name": field_info["name"],
                        "type": field_info.get("type", "unknown"),
                        "nullable": field_info.get("nullable", True),
                        "primary_key": field_info.get("primary_key", False),
                        "foreign_key": field_info.get("foreign_key"),
                        "unique": field_info.get("unique", False),
                        "indexed": field_info.get("indexed", False),
                        "default": field_info.get("default")
                    })
        
        return {
            "name": model_name.lower(),
            "model_class": model_name,
            "framework": "prisma",
            "file_path": file_path,
            "fields": fields,
            "relationships": relationships,
            "indexes": [],
            "constraints": []
        }

    def _parse_prisma_field_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single Prisma field line."""
        # Basic parsing: field_name field_type modifiers
        parts = line.split()
        if len(parts) < 2:
            return None
            
        field_name = parts[0]
        field_type = parts[1]
        
        field_info = {
            "name": field_name,
            "type": field_type,
            "is_relationship": False,
            "nullable": "?" in field_type,
            "primary_key": False,
            "unique": False,
            "indexed": False
        }
        
        # Remove optional modifier from type
        if field_type.endswith('?'):
            field_info["type"] = field_type[:-1]
        
        # Check if it's an array (relationship)
        if field_type.endswith('[]'):
            field_info["is_relationship"] = True
            field_info["relationship_type"] = "one-to-many"
            field_info["target_model"] = field_type[:-2]
        
        # Parse field modifiers
        modifiers = ' '.join(parts[2:])
        if '@id' in modifiers:
            field_info["primary_key"] = True
        if '@unique' in modifiers:
            field_info["unique"] = True
        if '@db.Index' in modifiers or '@@index' in modifiers:
            field_info["indexed"] = True
        if '@default' in modifiers:
            # Extract default value
            default_match = re.search(r'@default\(([^)]+)\)', modifiers)
            if default_match:
                field_info["default"] = default_match.group(1)
        
        return field_info

    def _find_migration_files(self) -> List[str]:
        """Find database migration files."""
        migration_files = []
        
        # Common migration patterns
        migration_patterns = [
            "**/migrations/**/*.py",
            "**/migrate/**/*.py",
            "**/db/migrate/**/*.py",
            "**/alembic/versions/**/*.py",
            "**/migrations/**/*.sql",
            "**/migrate/**/*.sql"
        ]
        
        for pattern in migration_patterns:
            files = self._find_files(pattern)
            migration_files.extend(files[:10])  # Limit to prevent overwhelming output
            
        return list(set(migration_files))  # Remove duplicates

    def _find_schema_files(self) -> List[str]:
        """Find database schema definition files."""
        schema_files = []
        
        # Schema file patterns
        schema_patterns = [
            "**/schema.prisma",
            "**/database.sql",
            "**/schema.sql",
            "**/create_tables.sql",
            "**/init.sql",
            "**/schema.py",
            "**/models.py",
            "**/db_schema.py"
        ]
        
        for pattern in schema_patterns:
            files = self._find_files(pattern)
            schema_files.extend(files)
            
        return list(set(schema_files))

    def _find_files(self, pattern: str) -> List[str]:
        """Find files matching a glob pattern."""
        try:
            files = []
            # Use pathlib to find files matching pattern
            for path in self.project_root.glob(pattern):
                if path.is_file():
                    files.append(str(path.relative_to(self.project_root)))
            return files
        except Exception:
            return []

    def _is_likely_model_file(self, file_path: str) -> bool:
        """Check if a file is likely to contain database models."""
        path_lower = file_path.lower()
        
        # Skip common non-model files
        skip_patterns = [
            'test', '__pycache__', '.pyc', 'migrations', 'alembic',
            'venv', '.venv', 'env', '.env', 'node_modules'
        ]
        
        for pattern in skip_patterns:
            if pattern in path_lower:
                return False
        
        # Look for model-like files
        model_indicators = [
            'model', 'schema', 'db', 'entity', 'table'
        ]
        
        return any(indicator in path_lower for indicator in model_indicators)

    def _extract_type_name(self, node: ast.AST) -> str:
        """Extract type name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id
            elif isinstance(node.func, ast.Attribute):
                return node.func.attr
        return "unknown"

    def _extract_default_value(self, node: ast.AST) -> str:
        """Extract default value from AST node."""
        if isinstance(node, ast.Constant):
            return str(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"{node.func.id}()"
        return "unknown"


def extract_database_schemas(project_root: str = ".") -> Dict[str, Any]:
    """
    Main function to extract database schemas from the project.
    
    Args:
        project_root: Path to the project root directory
        
    Returns:
        Dictionary containing structured schema information
    """
    try:
        extractor = DatabaseSchemaExtractor(project_root)
        return extractor.extract_database_schemas()
    except Exception as e:
        return {
            "tables": [],
            "frameworks": [],
            "migration_files": [],
            "schema_files": [],
            "total_tables": 0,
            "relationships_count": 0,
            "error": f"Schema extraction failed: {str(e)}"
        }


def extract_api_endpoints() -> Dict[str, Any]:
    """
    Extract API endpoint definitions from various web frameworks.
    Supports Flask, FastAPI, Django, and Express.js patterns.
    
    Returns:
        Dictionary containing:
        - endpoints: List of endpoint dictionaries with path, method, handler, framework, file
        - frameworks: List of detected API frameworks
        - total_endpoints: Total count of endpoints found
        - route_groups: Endpoints grouped by path prefix
    """
    api_context = {
        "endpoints": [],
        "frameworks": [],
        "total_endpoints": 0,
        "route_groups": {}
    }
    
    try:
        # Framework detection patterns
        framework_patterns = {
            "flask": ["from flask import", "app.route(", "@app.route", "Flask("],
            "fastapi": ["from fastapi import", "app.get(", "app.post(", "APIRouter", "FastAPI("],
            "django": ["urlpatterns", "path(", "re_path(", "from django.urls", "django.conf.urls"],
            "express": ["app.get(", "app.post(", "router.get(", "express.Router", "require('express')"]
        }
        
        # Find API-related files using secure subprocess
        api_files = []
        api_patterns = ["*routes*.py", "*urls*.py", "*api*.py", "*endpoints*.py", "*views*.py", "*.js", "*.ts"]
        
        for pattern in api_patterns:
            try:
                args = validate_subprocess_args(
                    ["find", ".", "-name", pattern, "-type", "f"],
                    allowed_commands=["find"]
                )
                result = subprocess.run(
                    args, capture_output=True, text=True, check=False, 
                    shell=False, timeout=5
                )
                if result.returncode == 0:
                    api_files.extend(result.stdout.splitlines()[:15])  # Limit per pattern
            except Exception:
                pass
        
        # Process each file (limit to 25 total files for performance)
        for file_path in list(set(api_files))[:25]:
            try:
                validated_path = validate_file_path(
                    file_path, base_dir=".", must_exist=True, allow_symlinks=False
                )
                
                with open(validated_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5000)  # Limit content read for performance
                
                # Detect framework
                detected_framework = None
                for framework, indicators in framework_patterns.items():
                    if any(indicator in content for indicator in indicators):
                        detected_framework = framework
                        if framework not in api_context["frameworks"]:
                            api_context["frameworks"].append(framework)
                        break
                
                # Extract endpoints based on framework
                endpoints = []
                if detected_framework == "flask":
                    endpoints = _extract_flask_endpoints(content, str(file_path))
                elif detected_framework == "fastapi":
                    endpoints = _extract_fastapi_endpoints(content, str(file_path))
                elif detected_framework == "django":
                    endpoints = _extract_django_endpoints(content, str(file_path))
                elif detected_framework == "express" and file_path.endswith(('.js', '.ts')):
                    endpoints = _extract_express_endpoints(content, str(file_path))
                
                api_context["endpoints"].extend(endpoints)
                
            except Exception:
                continue  # Skip problematic files
        
        # Group endpoints by prefix for better organization
        api_context["route_groups"] = _group_endpoints_by_prefix(api_context["endpoints"])
        api_context["total_endpoints"] = len(api_context["endpoints"])
        
        # Limit results for context injection performance
        api_context["endpoints"] = api_context["endpoints"][:30]
        
    except Exception:
        pass  # Return empty context on error
    
    return api_context


def _extract_flask_endpoints(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Extract Flask route definitions using regex patterns."""
    endpoints = []
    
    # Flask route patterns
    patterns = [
        r'@(?:app|bp|blueprint)\.route\s*\(\s*[\'"]([^\'"]+)[\'"](?:.*?methods\s*=\s*\[([^\]]+)\])?.*?\)\s*def\s+(\w+)',
        r'@(?:app|bp|blueprint)\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)[\'"].*?\)\s*def\s+(\w+)'
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
            if len(match.groups()) == 3:  # @app.route pattern
                path, methods_str, handler = match.groups()
                methods = ["GET"]  # Default
                if methods_str:
                    methods = [m.strip().strip('\'"') for m in methods_str.split(',')]
            else:  # @app.get pattern
                method, path, handler = match.groups()
                methods = [method.upper()]
            
            for method in methods:
                endpoints.append({
                    "path": path,
                    "method": method,
                    "handler": handler,
                    "framework": "flask",
                    "file": file_path
                })
    
    return endpoints


def _extract_fastapi_endpoints(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Extract FastAPI route definitions with modern async patterns."""
    endpoints = []
    
    # FastAPI route patterns
    patterns = [
        r'@(?:app|router)\.(get|post|put|delete|patch|options|head|trace)\s*\([\'"]([^\'"]+)[\'"].*?\)\s*(?:async\s+)?def\s+(\w+)',
        r'@(?:app|router)\.api_route\s*\([\'"]([^\'"]+)[\'"](?:.*?methods\s*=\s*\[([^\]]+)\])?.*?\)\s*(?:async\s+)?def\s+(\w+)'
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
            groups = match.groups()
            if pattern.endswith('(\\w+)') and len(groups) == 3:  # Direct method pattern
                method, path, handler = groups
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "handler": handler,
                    "framework": "fastapi",
                    "file": file_path
                })
            elif len(groups) == 3:  # api_route pattern
                path, methods_str, handler = groups
                methods = ["GET"]  # Default
                if methods_str:
                    methods = [m.strip().strip('\'"') for m in methods_str.split(',')]
                for method in methods:
                    endpoints.append({
                        "path": path,
                        "method": method,
                        "handler": handler,
                        "framework": "fastapi",
                        "file": file_path
                    })
    
    return endpoints


def _extract_django_endpoints(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Extract Django URL patterns from urls.py files."""
    endpoints = []
    
    # Django URL patterns
    patterns = [
        r'path\s*\(\s*r?[\'"]([^\'"]+)[\'"]\s*,\s*(\w+)',
        r're_path\s*\(\s*r?[\'"]([^\'"]+)[\'"]\s*,\s*(\w+)',
        r'url\s*\(\s*r?[\'"]([^\'"]+)[\'"]\s*,\s*(\w+)'
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            path, handler = match.groups()
            # Clean up regex patterns for display
            clean_path = path.replace('^', '').replace('$', '').replace('\\', '')
            if not clean_path.startswith('/'):
                clean_path = '/' + clean_path
                
            endpoints.append({
                "path": clean_path,
                "method": "GET/POST",  # Django views typically handle multiple methods
                "handler": handler,
                "framework": "django",
                "file": file_path
            })
    
    return endpoints


def _extract_express_endpoints(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Extract Express.js route definitions."""
    endpoints = []
    
    # Express route patterns
    patterns = [
        r'(?:app|router)\.(get|post|put|delete|patch|use|all)\s*\([\'"]([^\'"]+)[\'"]',
        r'router\.route\s*\([\'"]([^\'"]+)[\'"]\)(?:\.(?:get|post|put|delete|patch)\s*\([^)]*\))*'
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            groups = match.groups()
            if len(groups) == 2:
                method, path = groups
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "handler": "express_handler",
                    "framework": "express",
                    "file": file_path
                })
    
    return endpoints


def _group_endpoints_by_prefix(endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group endpoints by their path prefix for better organization."""
    groups = {}
    
    for endpoint in endpoints:
        path = endpoint["path"]
        # Extract first path segment as prefix
        parts = [p for p in path.split('/') if p]
        prefix = parts[0] if parts else "root"
        
        if prefix not in groups:
            groups[prefix] = []
        groups[prefix].append(endpoint)
    
    return groups


def get_database_context(user_prompt: str = "") -> Dict[str, Any]:
    """
    Get database schema AND API endpoint context for backend architecture tasks.
    Extracts relevant information based on prompt keywords.
    
    Args:
        user_prompt: User's prompt to determine context relevance
        
    Returns:
        Dictionary containing database schema and API endpoint information
    """
    # Database-related keywords
    db_keywords = [
        'database', 'db', 'sql', 'query', 'table', 'schema', 'model',
        'migrate', 'migration', 'index', 'performance', 'optimize',
        'sqlalchemy', 'django', 'prisma', 'orm', 'n+1', 'slow query'
    ]
    
    # API-related keywords
    api_keywords = [
        'api', 'endpoint', 'route', 'rest', 'graphql', 'http', 'request',
        'flask', 'fastapi', 'express', 'urls', 'views', 'controller',
        'microservice', 'service', 'backend', 'server'
    ]
    
    prompt_lower = user_prompt.lower()
    needs_db_context = any(keyword in prompt_lower for keyword in db_keywords)
    needs_api_context = any(keyword in prompt_lower for keyword in api_keywords)
    
    # If neither database nor API context is needed, return minimal info
    if not (needs_db_context or needs_api_context):
        return {"database_relevant": False, "api_relevant": False}
    
    context = {
        "database_relevant": needs_db_context,
        "api_relevant": needs_api_context,
        "frameworks": [],
        "tables": [],
        "endpoints": [],
        "total_tables": 0,
        "total_endpoints": 0,
        "relationships_count": 0,
        "route_groups": {}
    }
    
    # Extract database schema information if relevant
    if needs_db_context:
        schema_info = extract_database_schemas()
        context.update({
            "tables": schema_info.get("tables", []),
            "total_tables": schema_info.get("total_tables", 0),
            "relationships_count": schema_info.get("relationships_count", 0),
            "migration_files": schema_info.get("migration_files", []),
            "schema_files": schema_info.get("schema_files", [])
        })
        context["frameworks"].extend(schema_info.get("frameworks", []))
    
    # Extract API endpoint information if relevant
    if needs_api_context:
        api_info = extract_api_endpoints()
        context.update({
            "endpoints": api_info.get("endpoints", [])[:20],  # Limit for context
            "total_endpoints": api_info.get("total_endpoints", 0),
            "route_groups": api_info.get("route_groups", {})
        })
        context["frameworks"].extend(api_info.get("frameworks", []))
    
    # Remove duplicate frameworks
    context["frameworks"] = list(set(context["frameworks"]))
    
    return context
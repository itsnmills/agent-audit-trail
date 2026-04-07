#!/usr/bin/env python3
"""
Setup configuration for AI Agent Audit Trail Generator.

HIPAA-compliant audit trail and compliance reporting for AI agents
in healthcare networks.

Install:
    pip install -e .

CLI entry point after install:
    audit demo
    audit serve
    audit assess --start 2026-01-01
"""

from setuptools import setup, find_packages

setup(
    name="agent-audit-trail",
    version="1.0.0",
    description=(
        "AI Agent Audit Trail Generator — HIPAA-compliant audit logging "
        "and compliance reporting for AI agents in healthcare networks"
    ),
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Healthcare AI Security",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "sqlalchemy>=2.0.0,<3.0.0",
        "fastapi>=0.110.0,<1.0.0",
        "uvicorn[standard]>=0.27.0,<1.0.0",
        "reportlab>=4.1.0,<5.0.0",
        "jinja2>=3.1.0,<4.0.0",
        "pydantic>=2.0.0,<3.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            # Main CLI: audit <command>
            # §164.312(b): Command-line interface for audit trail management
            "audit=agent_audit.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Healthcare Industry",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Medical Science Apps.",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords=(
        "hipaa compliance audit healthcare ai agent "
        "security phi monitoring nist"
    ),
    project_urls={
        "Compliance Reference": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
        "NIST AI RMF": "https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf",
        "NIST SP 800-66r2": "https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final",
    },
)

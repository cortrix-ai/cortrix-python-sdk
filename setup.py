"""
Cortrix Security SDK — AI Agent Security Infrastructure.

pip install cortrix
"""
from setuptools import setup, find_packages

setup(
    name="cortrix",
    version="0.1.0a1",
    description="Cortrix Security SDK — Cryptographic identity, policy enforcement, and audit logging for AI agents",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Cortrix AI",
    author_email="sdk@cortrix.ai",
    url="https://github.com/cortrix-ai/cortrix-sdk",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24.0",
        "cryptography>=41.0.0",
    ],
    extras_require={
        "dev": ["pytest", "pytest-asyncio"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
)

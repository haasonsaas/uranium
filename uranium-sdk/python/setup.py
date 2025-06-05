from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="uranium-sdk",
    version="0.1.0",
    author="Jonathan Haas",
    author_email="jonathan@haasonsaas.com",
    description="Python SDK for Uranium Vault - Secure storage for LLM weights",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/haasonsaas/uranium",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "dataclasses>=0.6;python_version<'3.7'",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.20",
            "black>=22.0",
            "mypy>=0.990",
        ],
    },
)
# setup.py
from setuptools import setup, find_packages
import pathlib

HERE = pathlib.Path(__file__).parent
README_PATH = HERE / "README.md"

setup(
    name="aiwaf",
    version="1.1.5",
    description="AI-driven, self-learning Web Application Firewall for Python web applications",
    long_description=README_PATH.read_text(encoding="utf-8") if README_PATH.exists() else "AIWAF",
    long_description_content_type="text/markdown",
    author="Aayush Gauba",
    author_email="gauba.aayush@gmail.com",
    url="https://github.com/aiwaf-project/aiwaf",
    packages=find_packages(where="py", exclude=["tests*", "docs*"]),
    package_dir={"": "py"},
    python_requires=">=3.10",
    install_requires=[
        "aiwaf-rust>=0.2.4",
        "numpy>2",
        "pandas>2",
        "scikit-learn>=1.6.0",
        "geoip2>=5.0",
        "packaging>=20",
        "requests>=2.30",
        "python-whois>=0.9",
    ],
    extras_require={
        "django": [
            "Django>=5.0",
        ],
        "flask": [
            "Flask>=3.0",
            "Flask-SQLAlchemy>=3.0",
        ],
        "fastapi": [
            "fastapi>=0.100",
            "starlette>=0.30",
            "uvicorn>=0.20",
        ]
    },
    include_package_data=True,
    package_data={
        "aiwaf.core": ["geolock/*.mmdb"],
    },
    entry_points={
        "console_scripts": [
            "aiwaf=aiwaf.cli:main",
            "aiwaf-detect=aiwaf.cli:aiwaf_detect",
            "aiwaf-fast=aiwaf.fast.cli:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Django",
        "Framework :: Flask",
        "Framework :: FastAPI",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
    ],
)

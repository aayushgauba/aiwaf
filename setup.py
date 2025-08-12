# setup.py
from setuptools import setup, find_packages
import pathlib

HERE = pathlib.Path(__file__).parent

# read the long description from your README
long_description = (HERE / "README.md").read_text(encoding="utf-8")

setup(
    name="aiwaf",
    version="0.1.8.4",
    description="AI‑driven, self‑learning Web Application Firewall for Django",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Aayush Gauba",
    url="https://github.com/aayushgauba/aiwaf",
    license="MIT",
    packages=find_packages(exclude=["tests*", "docs*"]),
    python_requires=">=3.8",
    install_requires=[
        "Django>=3.2",
        "numpy>=1.21",
        "pandas>=1.3",
        "scikit-learn>=1.0",
        "joblib>=1.1",
    ],
    include_package_data=True,
    package_data={
        # include your pretrained model and any JSON resources
        "aiwaf": ["resources/*.pkl", "resources/*.json"]
    },
    entry_points={
        "console_scripts": [
            "aiwaf-detect=aiwaf.trainer:train",
        ]
    },
    classifiers=[
        "Framework :: Django",
        "Programming Language :: Python :: 3",
        "License :: MIT License",
    ],
)

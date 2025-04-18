from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="aiwaf",
    version="0.1.2",
    description="AI‑driven pluggable Web Application Firewall for Django (CSV or DB storage)",
    long_description=long_description,
    long_description_content_type="text/markdown",  # <- required for markdown support
    author="Aayush Gauba",
    packages=find_packages(),
    package_data={
        "aiwaf": ["resources/*.pkl"],
    },
    include_package_data=True,
    install_requires=[
        "django>=3.0",
        "scikit-learn",
        "numpy",
        "pandas",
        "joblib",
    ],
    entry_points={
        "console_scripts": [
            "aiwaf-detect=aiwaf.trainer:detect_and_train",
        ]
    },
)

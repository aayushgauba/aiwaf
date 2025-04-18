from setuptools import setup, find_packages

setup(
    name="aiwaf",
    version="0.1.0",
    description="AI‑driven pluggable Web Application Firewall for Django (CSV or DB storage)",
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

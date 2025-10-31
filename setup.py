#!/usr/bin/env python3

from pathlib import Path

from setuptools import find_packages, setup

PACKAGE_ROOT = Path(__file__).parent
README = (PACKAGE_ROOT / "README.md").read_text(encoding="utf-8")

setup(
    name="PEAS",
    version="1.0",
    description="ActiveSync client utilities for Python 3",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Adam Rutherford",
    author_email="adam.rutherford@mwrinfosecurity.com",
    packages=find_packages(include=["peas", "peas.*"]),
    python_requires=">=3.8",
    install_requires=[
        "Twisted[tls]>=22.10.0",
        "requests>=2.31.0",
        "lxml>=4.9.3",
        "zope.interface>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "peas=peas.__main__:main",
        ],
    },
    include_package_data=True,
)

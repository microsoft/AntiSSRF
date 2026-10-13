import os
from setuptools import setup

# All static metadata lives in pyproject.toml. Only the version is set here
setup(version=os.environ.get("PACKAGE_VERSION", "1.0.0"))

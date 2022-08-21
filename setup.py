from setuptools import setup,find_packages

setup(name="signEverywhere",
        version="0.1",
        description="Sign and verify file everywhere",
        packages=find_packages(),
        install_requires=["argon2","cffi","pycparser","PySPX"],
        )

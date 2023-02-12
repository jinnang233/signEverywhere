from setuptools import setup,find_packages

setup(name="signEverywhere",
        version="0.1.2",
        description="Sign and verify file everywhere",
        packages=["signEverywhere"],
        install_requires=["argon2","cffi","pycparser","PySPX","kademlia"],
        entry_points={
            'console_scripts': [
                'sign_everywhere = signEverywhere.main:main'
            ]
        },
        package_data = {
            "signEverywhere":["locales/*/LC_MESSAGES/*.mo"],
        },
        include_package_data=True,
        )
        

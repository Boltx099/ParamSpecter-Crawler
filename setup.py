from setuptools import setup

setup(
    name="paramspecter",
    version="5.0",
    description="Advanced Recon Crawler for Bug Bounty and Security Research",
    author="Boltx",
    py_modules=["ParamSpecter"],
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "dnspython>=2.4.0",
        "fake-useragent>=1.4.0",
        "tqdm>=4.66.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "playwright": ["playwright>=1.40.0"],
        "db": [
            "pymongo>=4.6.0",
            "psycopg2-binary>=2.9.9",
        ],
    },
    entry_points={
        "console_scripts": [
            "paramspecter=ParamSpecter:main",
        ],
    },
    python_requires=">=3.8",
)

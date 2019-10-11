"""SIP/RTP parser"""
import os

from setuptools import setup, find_packages

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

setup(
    name='sip-parser',
    version='0.1.0',
    description='SIP/RTP parser',
    packages=['sip_parser'],
    python_requires='>=3.6',
    zip_safe=True,

    classifiers=[
        "Intended Audience :: Customer Service",
        "Intended Audience :: Telecommunications Industry",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6"],
)

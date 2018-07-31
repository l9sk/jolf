#!/usr/bin/env python

from setuptools import setup
import sys

if sys.version_info[0] == 3 and sys.version_info[1] < 4:
    sys.exit('Sorry, Python < 3.4 is not supported')

def readme():
    with open("README.md") as f:
        return f.read()

setup(
    name='',
    version='0.1',
    packages=['jolf'],
    url="",
    author="Saahil Ognawala",
    author_email="saahil.ognawala@tum.de",
    license="Apache Software License",
    packages=["jolf"],
    entry_points={
        'console_scripts': [
            'jolf = jolf.__main__',
        ]
    },
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ]
)

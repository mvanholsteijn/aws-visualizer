# -*- coding: utf-8 -*-


"""setup.py: setuptools control."""


import re
from setuptools import setup
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), 'r') as f:
    long_description = f.read()

version="0.1.0"

setup(
    name = "aws-visualizer",
    packages = ["aws_visualizer", "aws_visualizer.neo4j", "aws_visualizer.dot" ],
    entry_points = {
        "console_scripts": ['aws-neo4j = aws_visualizer.neo4j:main', 'aws-dot = aws_visualizer.dot:main' ]
        },
    version = version,
    description = "A visualizer of the network of security group dependencies in an AWS VPC.",
    long_description=long_description,
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=['boto3', 'netaddr', 'neomodel'],
    author = "Mark van Holsteijn",
    author_email = "mark@binx.io",
    url = "https://github.com/mvanholsteijn/aws-visualizer",
    )

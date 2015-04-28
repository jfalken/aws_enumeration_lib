from setuptools import setup

requires = [
    "boto==2.38.0",
    "wsgiref==0.1.2"]

setup(
    name="ase",
    url="https://github.com/jfalken/aws_enumeration_lib",
    description='AWS Multi Account/Region Asset enumeration wrapper',
    version="1.0",
    py_modules=['ase'],
    install_requires=requires)

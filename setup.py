#!/usr/bin/python3

from setuptools import setup, Extension
from Cython.Distutils import build_ext

setup(
    name='org_wayround_gsasl',
    version='0.1',
    description='Python gsasl binding',
    packages=[
        'org.wayround.gsasl'
        ],
    ext_modules=[
        Extension(
            "org.wayround.gsasl.gsasl",
            ["org/wayround/gsasl/gsasl.pyx"],
            libraries=["gsasl"]
            # TODO: pkg-config
            )
        ],
    cmdclass={'build_ext': build_ext},
    package_data={'org.wayround.gsasl': ['*.pxd']},
    )

#!/usr/bin/python3

from setuptools import setup, Extension
from Cython.Distutils import build_ext

setup(
    name='wayround_org_gsasl',
    version='0.2.1',
    description='Python gsasl binding',
    packages=[
        'wayround_org.gsasl'
        ],
    ext_modules=[
        Extension(
            "wayround_org.gsasl.gsasl",
            ["wayround_org/gsasl/gsasl.pyx"],
            libraries=["gsasl"]
            # TODO: pkg-config
            )
        ],
    cmdclass={'build_ext': build_ext},
    package_data={'wayround_org.gsasl': ['*.pxd']},
    )

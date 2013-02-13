#!/usr/bin/python3

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    name='org_wayround_gsasl',
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

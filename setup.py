#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
$ python setup.py register sdist upload

First Time register project on pypi
https://pypi.org/manage/projects/


More secure to use twine to upload
$ pip3 install twine
$ python3 setup.py sdist
$ twine upload dist/keria-0.0.1.tar.gz


Update sphinx /docs
$ cd /docs
$ sphinx-build -b html source build/html
or
$ sphinx-apidoc -f -o source/ ../src/
$ make html

Best practices for setup.py and requirements.txt
https://caremad.io/posts/2013/07/setup-vs-requirement/
"""


from glob import glob
from os.path import basename
from os.path import splitext
from setuptools import find_packages
from setuptools import setup

setup(
    name='cesr-verifier',
    version='0.0.1',  # also change in src/verifier/__init__.py
    description='CESR Verifier',
    long_description="CESR Verifier",
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Utilities',
    ],
    project_urls={
        'Issue Tracker': 'https://github.com/provenant-dev/cesr-verifier',
    },
    keywords=[
        "secure attribution",
        "authentic data",
        "discovery",
        "resolver",
    ],
    python_requires='>=3.12.2',
    install_requires=[
        'keri @ git+https://git@github.com/provenant-dev/keripy.git@v1.1.6-pr9',
        'mnemonic>=0.20',
        'multicommand>=1.0.0',
        'falcon>=3.1.0',
        'http_sfv>=0.9.8',
        'dataclasses_json>=0.5.7',
        'apispec>=6.3.0',
        'requests>=2.31.0',
    ],
    extras_require={
        # eg:
        #   'rst': ['docutils>=0.11'],
        #   ':python_version=="2.6"': ['argparse'],
    },
    tests_require=[
        'coverage>=5.5',
        'pytest>=6.2.4',
    ],
    setup_requires=[
    ],
    entry_points={
        'console_scripts': [
            'verifier = verifier.app.cli.verifier:main',
        ]
    },
)

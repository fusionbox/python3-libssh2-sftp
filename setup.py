import os

from setuptools import setup

def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as fp:
        return fp.read()


setup(
    name='python3-libssh2-sftp',
    version='0.1.0',

    description='Python3 bindings for the SFTP features of libssh2',
    long_description=read('README.txt'),

    url='https://github.com/fusionbox/python3-libssh2-sftp',

    author='Fusionbox, Inc.',
    author_email='programmers@fusionbox.com',

    license='Proprietary',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],

    keywords='ssh fast libssh2 sftp client',

    packages=['libssh2_sftp'],

    install_requires=['cffi'],
)

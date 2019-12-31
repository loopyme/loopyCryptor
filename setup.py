from setuptools import setup, find_packages

setup(
    name='loopyCryptor',
    version='0.0.1',
    description=(
        'Easy-to-use string symmetric/asymmetric encryption tools based on PyCryptodome'
    ),
    author='loopyme',
    author_email='peter@mail.loopy.tech',
    maintainer='loopyme',
    maintainer_email='peter@mail.loopy.tech',
    license='MIT License',
    packages=find_packages(),
    platforms=["all"],
    install_requires=[
        'pycryptodome>=3.9.4',
    ]
)

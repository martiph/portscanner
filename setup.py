from setuptools import setup

setup(
    name='portscanner',
    version='0.1',
    packages=[''],
    url='https://github.com/martiph/portscanner',
    license='MIT',
    author='martiph',
    author_email='martiph@gmx.ch',
    description='a simple portscanner',
    py_modules=['portscanner'],
    entry_points={
        'console_scripts': ['portscanner=portscanner:main']
    },
    install_requires = ['']
)

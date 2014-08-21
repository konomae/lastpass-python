from setuptools import setup


def get_version():
    import re
    with open('lastpass/__init__.py', 'r') as f:
        for line in f:
            m = re.match(r'__version__ = [\'"]([^\'"]*)[\'"]', line)
            if m:
                return m.group(1)
    raise RuntimeError('Cannot find version information')


setup(
    name='lastpass-python',
    version=get_version(),
    description='LastPass Python API (unofficial)',
    long_description=open('README.rst').read(),
    license='MIT',
    author='konomae',
    author_email='konomae@users.noreply.github.com',
    url='https://github.com/konomae/lastpass-python',
    packages=['lastpass'],
    install_requires=[
        "requests>=1.2.1,<=3.0.0",
        "pycrypto>=2.6.1",
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
)
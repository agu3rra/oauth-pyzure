from setuptools import setup, find_packages

setup(
    name='oauth-pyzure',
    version='0.1.3',
    packages=find_packages(),
    install_requires=['requests==2.24.0','cryptography==3.1.1','pyjwt==1.7.1'],
    author='Andre Guerra',
    author_email='agu3rra@gmail.com',
    description='OAuth Pyzure: OAuth for Python with Azure',
    long_description='Simple OAuth client_credential flow with Azure for Python.',
    url='https://github.com/agu3rra/oauth-pyzure',
    license='MIT',
    keywords='api oauth authorization azure client credentials flow'
)

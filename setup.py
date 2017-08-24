from setuptools import setup, find_packages

setup(
    name='buttersalt_ldap',
    description='LDAP management plugin',
    version='1.0.1',
    author='lfzyx',
    author_email='lfzyx.me@gmail.com',
    url='https://github.com/lfzyx/ButterSalt-LDAP',
    license='MIT',
    classifiers=[
        'Development Status :: 1 - Planning',
        'Programming Language :: Python :: 3 :: Only',
        ],
    python_requires='>=3.5.3',
    keywords='buttersalt ldap',
    packages=find_packages(),
    package_data={
        'buttersalt_ldap': ['templates/*/*.html'],
    },
)

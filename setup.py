from setuptools import setup, find_packages

setup(
    name='buttersalt_ldap',
    description='LDAP management plugin',
    version='1.0.4',
    author='lfzyx',
    author_email='lfzyx.me@gmail.com',
    url='https://github.com/lfzyx/ButterSalt-LDAP',
    license='MIT',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Programming Language :: Python :: 3 :: Only',
        'Framework :: Flask',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    python_requires='>=3.5.3',
    keywords='buttersalt ldap',
    packages=find_packages(),
    package_data={
        'buttersalt_ldap': ['templates/*/*.html'],
    },
)

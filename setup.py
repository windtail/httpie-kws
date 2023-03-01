from setuptools import setup

try:
    import multiprocessing
except ImportError:
    pass

setup(
    name='httpie-kws',
    description='KWS plugin for HTTPie.',
    python_requires=">=3.7",
    long_description=open('README.md').read().strip(),
    version='1.0.0',
    author='Luo Jiejun',
    author_email='ljj@knd.com.cn',
    license='Apache 2.0',
    url='https://github.com/windtail/httpie-kws',
    download_url='https://github.com/windtail/httpie-kws',
    py_modules=['httpie_kws'],
    zip_safe=False,
    entry_points={
        'httpie.plugins.auth.v1': [
            'httpie_kws_auth = httpie_kws:KwsAuthPlugin'
        ]
    },
    install_requires=[
        'httpie == 3.2.1',
    ],
)

from setuptools import setup
setup(
  name = 'cryptex',
  packages = ['cryptex'],
  version = "1.1.1",
  description = 'Easy and safe file/password storage encrypted globally',
  author = 'Brandon Gillespie',
  author_email = 'bjg-pypi@cold.org',
  url = 'https://github.com/srevenant/cryptex',
  keywords = ['password', 'storage'],
  install_requires = [
    'pynacl',
    'boto',
    'dictlib'
  ],
  entry_points = {
    'console_scripts': [
      'cryptex=cryptex:main',
      'vicryptex=cryptex:main',
      'cx=cryptex:main',
      'vicx=cryptex:main'
    ]
  },
  classifiers = [],
)


from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='pcap_to_ditg',
      version='1.0.1',
      description='Generate DITG script files from a pcap file',
      url='http://github.com/devenbansod/pcap_to_DITG',
      author='Deven Bansod',
      author_email='devenbansod.bits@gmail.com',
      long_description=long_description,
      long_description_content_type="text/markdown",
      license='LICENSE',
      packages=['pcap_to_ditg'],
      install_requires=[
          'dpkt',
      ],
      zip_safe=False,
      classifiers=[
          "License :: OSI Approved :: MIT License",
          "Operating System :: OS Independent",
      ])

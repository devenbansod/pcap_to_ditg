from setuptools import setup

setup(name='pcap_to_ditg',
      version='0.1.1',
      description='Generate DITG script files from a pcap file',
      url='http://github.com/devenbansod/pcapToDITG',
      author='Deven Bansod',
      author_email='devenbansod.bits@gmail.com',
      license='LICENSE',
      packages=['pcap_to_ditg'],
      install_requires=[
          'dpkt',
      ],
      zip_safe=False)

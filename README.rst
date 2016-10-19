pcapToDITG
==========

Generates [DITG's] (http://traffic.comics.unina.it/software/ITG/) flow
definition Files for each IP using a Packet Capture (.pcap) file as
input

Installation
------------

-  The package is available to be installed through `PyPI - the Python
   Package Index <https://pypi.python.org/pypi>`__
-  You can install the latest version by running:

   ::

       $ sudo pip install pcap_to_ditg

-  The latest release can be also downloaded from the `Github
   repository <https://github.com/devenbansod/pcapToDITG/releases>`__

Usage
-----

-  The help section of the program describes the usage details

   ::

       usage: pcap_to_ditg.py [-h] [-t START_TIME] [-e END_TIME] [-r] [-s] [-p] [-c]
                          pcap_file mapper_file list_file

       Generate DITG script files from a pcap file

       positional arguments:
         pcap_file             .pcap file to be used in generation
         mapper_file           Mapper file to be used in generation
         list_file             File containing all distinct IPs to be used in
                               generation

       optional arguments:
         -h, --help            show this help message and exit
         -t START_TIME, --start-time START_TIME
                               Timestamp (in sec) from which the file should be read
         -e END_TIME, --end-time END_TIME
                               Timestamp (in sec) until which the file should be read
         -r, --remove-old      Remove any older generated files if present before
                               generating new files
         -s, --same-dir        File containing all distinct IPs to be used in
                               generation
         -p, --print-all-ips   Print all distinct IPs appearing in the pcap file and
                               exit
         -c, --clean           Remove any older generated files and exit the program

-  The format of ``list_file`` is as follows:

   ::

       10.0.1.10,
       10.0.2.10,
       .
       .
       .

   -  These are the IPs that are appearing in the PCAP file (as
      specified by ``pcap_file`` argument)
   -  You can generate this list automatically by running the program
      with ``-p`` option

      ::

          $ touch list_file
          $ python pcap_to_ditg.py -p pcap_file mapper_file list_file > list_file

   -  **Note**: While running the program with ``-p`` option, the files
      ``mapper_file`` and ``list_file`` are not actually used but still
      have to be provided as argument and should exist.

-  The format of ``mapper_file`` is as follows:

   ::

       Host,Start_row,End_row,Number
       h1,1734,1902,169
       h2,1528,1733,206
       .
       .
       .



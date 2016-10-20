pcap_to_ditg
============

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

-  The help section of the `run.py` program describes the usage details

   ::

        usage: run.py [-h] [-t START_TIME] [-e END_TIME] [-s PACKET_SIZE_OPTIONS] [-p]
              [-c]
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
          -s PACKET_SIZE_OPTIONS, --packet-size-options PACKET_SIZE_OPTIONS
                                Packet size options to be used for each flow (for ex.
                                For Anonymized trace pcap files). If not provided,
                                *_ps files are created for each flow by using packet
                                sizes as per the pcap file
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
   -  You can generate this list automatically by running the example program
      with ``-p`` option

      ::

          $ touch list_file
          $ python run.py -p pcap_file mapper_file list_file > list_file

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

-  Usage in a different script or in interpreter mode is as:

   ::

       >> from pcap_to_ditg import pcap_to_ditg
       >> pcap_file_path = '***'
       >> mapper_file_path = '***'
       >> list_file_path = '***'
       >> options = {'end_time' : 60}
       >> p = pcap_to_ditg.pcap_to_ditg(
            pcap_file_path,
            mapper_file_path,
            list_file_path,
            options
          )
       The flow scripts and the IDT files have been generated and have been saved in separate sub-folders *_ditg_files.
       >>


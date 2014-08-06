PortStealer v.0.1
=================

A Man-In-The-Middle tool, not using ARP responses, but stealing the port of the switch of the victim, changing its association in the CAM table.

How it works
------------

A DNS packet is injected on the network, with the source MAC address of the victim. After that, the switch associates the victim MAC to the port of the attacker.

The tool stores the sniffed packets (the packets the victim should have received) and, after a short time, reinject them to the victim.

Periodically, stealing packets are reinjected, since when the victim generates traffic the original port association is restored.

When stopped, the program restore the CAM table, generating an ARP query to the victim (when the victim answers it, the port association is restored).

Extra
-----

A project born after a lunch at a local "rosticceria" with my colleagues,
during my first university year in l'Aquila.

A greeting to Tiziano, Ivan, Lorenzo, Cesare, Davide, Daniele, and the rest of them :)

License
-------

License: BSD License (2011)


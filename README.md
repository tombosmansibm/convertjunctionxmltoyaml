Usage
------
Extract the webseal-config.zip file you obtained by exporting the junction configuration.
We need the "junctions" directory.

start main.py, and select the "junctions directory"

The output is separate yaml files you can use in plays that are built for https://github.com/IBM-Security/isam-ansible-collection

Specifically:
 https://github.com/IBM-Security/isam-ansible-collection/tree/master/roles/web/configure_reverseproxy_junctions

To do
-------
- so far , the output yaml file is not tested yet (not deployed yet)
- logic for the http/https ports needs to be verified
- a lot of fields are ignored at this time
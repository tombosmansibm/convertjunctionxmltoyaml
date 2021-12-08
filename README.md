Usage
------
Extract the webseal-config.zip file you obtained by exporting the junction configuration.
We need the "junctions" directory.

Alternatively, you can also get a snapshot, this makes more sense if you have a lot of instances to process.


The configuration directory can be found under /var/pdweb/{name of instance}/server-root/jct


This is tested on Linux and Windows.

It requires Python 3.6+

     
install the prerequisites (in a virtual env)

run headless

    cd <directory>
    isamjunction/main.py --junctiondir=<directory to junctions>
    

run with prompt
   
    cd <directory>
    isamjunction/main.py


select the "junctions directory"

There's 2 flavors:
- <junction_name>.yml
- junctions.yml

The 2nd output is 1 yaml file you can use in plays that are built for https://github.com/IBM-Security/isam-ansible-collection

Specifically:
 https://github.com/IBM-Security/isam-ansible-collection/tree/master/roles/web/configure_reverseproxy_junctions


The first format are individual files , that need specific care to be deployed, but they match the xml files 1-to-1

To do
-------
- logic for the http/https ports needs to be verified

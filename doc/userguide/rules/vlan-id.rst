Vlan.id Keyword
===============

Suricata has a ``vlan.id`` keyword that can be used in signatures to identify
and filter network packets based on Virtual Local Area Network IDs. By default,
it matches all VLAN IDs. However, if a specific layer is defined, it will only match that layer.

Syntax::

 vlan.id: id[,layer];

Signature examples::

 alert ip any any -> any any (msg:"Vlan ID is equal to 300"; vlan.id:300; sid:1;)

::

 alert ip any any -> any any (msg:"Vlan ID is equal to 300"; vlan.id:300,1; sid:1;)
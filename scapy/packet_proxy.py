## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Aaron Wood <woody77@gmail.com>
## This program is published under a GPLv2 license

from packet import NoPayload

"""
Pickleable Proxy for a Scapy Packet

This is a pickleable object that only holds the layer type and the field values, so that it can be
un/pickled very, very quickly.

The proxy does _not_ duplicate lists, as it's meant to be a proxy for pickling (which does), so it
is inherently unsafe to use this to create a new Packet object in the same process (it will by it's
nature share the internal field and aliastypes lists with the original packet).
"""


def create_layer_tuple_list(p, layers):
    """recursively extract tuples of layer type and fields"""
    if type(p) is not NoPayload:
        layers.append((p.__class__, p.fields))
        create_layer_tuple_list(p.payload, layers)
    return layers

def create_layer(layer_tuple):
    """recreate a Packet layer from the tuple above"""
    alias,fields = layer_tuple
    layer = alias()
    layer.fields = fields
    return layer



class PacketProxy:

    def __init__(self, p):
        self.ts = p.time
        self.layer_tuples = create_layer_tuple_list(p, [])

    def create_packet(self):
        """creates a packet from the type and field data"""
        layers = map(create_layer, self.layer_tuples)
        for layer in layers:
            try:
                prev.payload = layer
                prev = layer
            except UnboundLocalError:
                base = layer
                prev = layer
        base.time = self.ts
        return base

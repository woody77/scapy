## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Aaron Wood <woody77@gmail.com>
## This program is published under a GPLv2 license

from multiprocessing import Pool
from collections import deque

from packet import Raw
from layers.l2 import Ether
from utils import *
from packet_proxy import *

"""
This is a parallelized reader of pcap files, which can use multiple cores to do
the Raw->Packet parsing.  It relies on a proxy format for the packets which may
be incomplete (It Works For Me (TM))

The deeper that packets are being parsed, the more likely this will be of benefit.
"""

def parse_packet(rp):
    """
        Takes a raw packet and parses it into a fully valid Packet for returning
        rp: the raw packet
        """
    
    s,(sec,usec,wirelen) = rp
    
    try:
        p = Ether(s)
    except KeyboardInterrupt:
        raise
    except:
        p = Raw(s)
    p.time = sec+0.000001*usec
    return PacketProxy(p)



class ParallelPcapReader(PcapReader):
    """
    A parallelized pcap reader to improve the performance of constructing Packets from pcap objects
    
    filename = file to open
    pool_size = the number of worker threads to use (num cores seems best)
    read_ahead = the number of packets to read in a big blob, and dispatched to the worker pool
    """
    def __init__(self, filename, pool_size=2, read_ahead=1000):
        PcapReader.__init__(self, filename)
        self.readahead = deque() #this is the read-ahead queue that we read into, and return packets from,
        self.finished = False
        self.pool = Pool(pool_size)
        self.read_ahead = read_ahead
    
    
    def read_packet(self):
        # flag that we've finished reading
        if len(self.readahead) == 0:
            if self.finished:
                return None
            # read-ahead packets
            rps = []
            for i in xrange(self.read_ahead):
                rp = RawPcapReader.read_packet(self)
                if rp is None:
                    self.finished = true
                    break
                else:
                    rps.append(rp)
        
            ppkts = self.pool.map(parse_packet,rps)
            self.readahead.extend(ppkts) # holds PacketProxies
        
        if len(self.readahead) > 0:
            return self.readahead.popleft().create_packet() # returns Packet from PacketProxy
        else:
            return None
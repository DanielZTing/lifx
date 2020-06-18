"""
Python interface for the LIFX LAN protocol.
"""

import logging
logger = logging.getLogger('scapy')
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

from scapy.all import *

class LIFX(Packet):
    """
    Bare-bones implementation of the LIFX header. By default, this sends
    a Device::GetService request to the broadcast address to perform
    device discovery. Users will have to set the fields manually.

    XXX: This currently ignores the required little endian byte ordering
    when bytes are split across multiple fields.
    """
    name = 'LIFX LAN'
    HEADER_SIZE = 36
    fields_desc = [
        # Frame
        LEShortField('size', HEADER_SIZE),
        BitField('protocol', 1024, 12),
        BitField('addressable', 1, 1),
        BitField('tagged', 1, 1),
        BitField('origin', 0, 2),
        LEIntField('source', 0),
        # Frame Address
        LELongField('target', 0),
        BitField('reserved', 0, 48),
        BitField('res_required', 1, 1),
        BitField('ack_required', 1, 1),
        BitField('reserved', 0, 6),
        ByteField('sequence', 0),
        # Protocol Header
        LongField('reserved', 0),
        LEShortField('type', 2),
        ShortField('reserved', 0),
    ]

if __name__ == '__main__':
    interact(mydict=globals(), mybanner='Scapy LIFX LAN Protocol API')

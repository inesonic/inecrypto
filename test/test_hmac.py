#!/usr/bin/python
#-*-python-*-##################################################################
# Copyright 2016 Inesonic, LLC
# All Rights Reserved
###############################################################################

"""
This Python module includes a small function to calculate HMACs.

"""

###############################################################################
# Import:
#

import re
import sys
import hashlib
import hmac

###############################################################################
# Globals:
#

__version__ = int(re.sub(r'.*: *([0-9]+).*',r'\1',"$Rev: 211 $"))
"""
Holds the Subversion revision number of this module.

:type: int

"""

HASH_ALGORITHM = hashlib.sha256
"""
The SHA hash used to calculate HMACs.

"""

###############################################################################
# Functions:
#

def hex_string(s):
    """
    Converts a string of bytes to a sequence of space separated hex bytes.

    :param s:
        The string to convert.

    :type s: str

    :return:
        Returns the hex string.

    :rtype: str

    """

    hs = ""
    for x in bytearray(s):
        hs += "%02X"%x

    return hs

###############################################################################
# Main:
#

assert(len(sys.argv) == 3)

key = sys.argv[1]
data = sys.argv[2]

h = hmac.HMAC(key, data, HASH_ALGORITHM)

print "\"%s\" << \"%s\" << \"%s\""%(
    hex_string(key),
    hex_string(data),
    hex_string(h.digest())
)

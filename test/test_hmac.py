#!/usr/bin/python
#-*-python-*-##################################################################
# Copyright 2016 - 2022 Inesonic, LLC
#
# MIT License:
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation
#   the rights to use, copy, modify, merge, publish, distribute, sublicense,
#   and/or sell copies of the Software, and to permit persons to whom the
#   Software is furnished to do so, subject to the following conditions:
#   
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#   
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#   DEALINGS IN THE SOFTWARE.
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

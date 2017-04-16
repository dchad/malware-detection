# gzip_pickle.py
#
# Modified to use cPickle instead of pickle
#
# Derek Chadwick
# 16/04/2017



"""Generic object pickler and compressor

This module saves and reloads compressed representations of generic Python
objects to and from the disk. Added Protocol field.
"""

__author__ = "Bill McNeill <billmcn@speakeasy.net>"
__version__ = "1.1"

import cPickle
import gzip


def save(object, filename, protocol = 0):
        """Saves a compressed object to disk
        """
        file = gzip.GzipFile(filename, 'wb')
        file.write(cPickle.dumps(object, protocol))
        file.close()

def load(filename):
        """Loads a compressed object from disk
        """
        file = gzip.GzipFile(filename, 'rb')
        buffer = ""
        while True:
                data = file.read()
                if data == "":
                        break
                buffer += data
        object = cPickle.loads(buffer)
        file.close()
        return object




if __name__ == "__main__":
        import sys
        import os.path
        
        class Object:
                x = 7
                y = "This is an object."
        
        filename = sys.argv[1]
        if os.path.isfile(filename):
                data = load(filename)
                z,l = data[0],data[1]
                print "Loaded %s" % data
                print "z.x = %d z.y = %s" % (z.x,z.y)
                print "list = %s" % l
        else:
                z = Object()
                z.x = 666
                l = [2,4,9]
                data = (z,l)
                save(data, filename)
                print "Saved %s" % data
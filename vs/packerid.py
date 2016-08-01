#!/usr/bin/python
#
# Author: Jim Clausing
# Date:   2009-05-15
# Version: 1.4
# Description: I really like PEiD (http://peid.has.it), but it is
#	Windows only and I haven't been able to get it to just output
#	the packers from the commandline (if it can be done, let me
#	know how), so I wrote this script which uses a PEiD database
#	to identify which packer (if any) is being used by a binary.
#	I wrote this for 3 primary reasons:
#	packer (if any) is being used by a binary.
#	  1) I wanted a command line tool that run on Linux/Unix/OSX
#	  2) I figured it was time to teach myself Python
#	  3) Ero Carrera had done the hard part with pefile :)
#
# Thanx to Ero Carrera for creating peutils and pefile.
# Thanx to BobSoft for his great PEiD database at http://www.secretashell.com/BobSoft/
# Thanx to the authors of PEiD for a really useful tool.useful.
#
# 2007-10-08 - fix a problem where I left out 'print'
# 2007-10-25 - add -V switch to print out version number
# 2009-05-15 - added some error handling as recommended by Joerg Hufschmidt
#

import peutils
import pefile
import sys
from optparse import OptionParser

version = "1.3"
usage = "usage: %prog [options] file [file ...]"
parser = OptionParser(usage)
parser.add_option("-a","--all", dest="show_all",
		  help="show all PE info", default=False,
		  action="store_true")
parser.add_option("-D", "--database", dest="alt_db",
		  help="use alternate signature database DB", metavar="DB")
parser.add_option("-m", "--all-matches", dest="show_matches",
                  help="show all signature matches", default=False,
                  action="store_true")
parser.add_option("-V", "--version", dest="version",
                  help="show version number", default=False,
                  action="store_true")

(options, args) = parser.parse_args()

if options.version:
    print "Packerid.py version ",version,"\n Copyright (c) 2007, Jim Clausing"
    sys.exit(0)

if len(args) < 1:
    parser.error("no files specified")

if options.alt_db:
    signatures = peutils.SignatureDatabase(options.alt_db)
else:
    signatures = peutils.SignatureDatabase('/usr/local/etc/userdb.txt')

for file in args:

  try:
    pe = pefile.PE(file)
  except:
    print file, ":  ### ERROR ###"
    continue

  if options.show_all|options.show_matches:
    matches = signatures.match_all(pe, ep_only = True)
  else:
    matches = signatures.match(pe, ep_only = True)

  if len(args) > 1:
    print file, ": ",  matches
  else:
    print matches

  if options.show_all:
    print pe.dump_info()

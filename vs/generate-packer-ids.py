# Generate unique scalar value for each packer type to use as a training feature
# for malware sample set. Note: userdb-sans.txt is a PEid.exe database, it has
# been modified to remove things like commas in the packer name to make processing
# and matching easier. 
#
# Input : userdb-sans.txt
#         entry format = [packer_name]
#                        [signature (hex encoded)]
#                        [flags]
#
# Output: packer-id.csv
#         row format = [packer_name, id]
#
# Author: Derek Chadwick
# Date  : 04/08/2016


import os
import re

# This is one of the packer ID databases used by PEid.exe
fip = open('data/userdb-sans.txt', 'r')
in_lines = fip.readlines()
fop = open('data/packer-id.csv','w')
fop.write('packer_name,packer_id\n')
fop.write('unknown,0\n')
p1 = re.compile('\[(.*)\]')
out_lines = []
row = ' '
counter = 0
for idx, line in enumerate(in_lines):
    if line.startswith('['):
        counter += 1
        m = p1.match(line)
        if m != None:
            row = m.group(1) + ',' + str(counter) + '\n'
            out_lines.append(row)
        else:
            continue
    else:
        continue
    
    if (idx % 100) == 0: # print progress
        fop.writelines(out_lines)
        out_lines = []
        print('Filename: {:s} - {:d}'.format(row.rstrip(),idx))
        

if len(out_lines) > 0:
    fop.writelines(out_lines)
    out_lines = []

fip.close()
fop.close()

print('Completed {:d} packer IDs.'.format(counter))
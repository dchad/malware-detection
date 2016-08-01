import os

fip = open('data/malok.csv', 'r')
in_lines = fip.readlines()
len(in_lines)


idx = 0
ext_drive = '/opt/vs/train/'
ext_drive2 = '/opt/vs/train2/'
# make a shell script for this one for efficiency
fop = open('cpmals.sh','w')
fop.write('#!/bin/bash\n')
out_lines = []

for idx in range(1,len(in_lines)):
    tokens = in_lines[idx].split(',')
    file_name = ext_drive + 'VirusShare_' + tokens[0]
    if os.path.isfile(file_name):
        cpcmd = 'cp ' + file_name + " ~/project/reference/opensecurity/tools/vs/\n"
    else:
        file_name = ext_drive2 + 'VirusShare_' + tokens[0]
        if os.path.isfile(file_name):
            cpcmd = 'cp ' + file_name + " ~/project/reference/opensecurity/tools/vs/\n"
        else:
            continue
    
    out_lines.append(cpcmd)
    if (idx % 100) == 0: # print progress
        fop.writelines(out_lines)
        print('Filename: {:s} - {:d}'.format(file_name,idx))
        

if len(out_lines) > 0:
    fop.writelines(out_lines)

fip.close()
fop.close()

print('Completed {:d} files.'.format(idx))

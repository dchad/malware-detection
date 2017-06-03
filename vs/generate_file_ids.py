# generate_file_ids.py
#
# DEPRECATED
#
# NOTE: This does not get a complete list of magic signatures as the "file -l"
#       command does not produce a complete list of signatures.
#       
# TODO: Modify file id feature extraction to do dynamic updates of the 
#       file id database. Also add a TrID database.
#
# Generate unique scalar value for each file type to use as a training feature
# for malware sample set. Uses the file types from the magic database used
# by the "file" command. Also uses the linux version of TrID.
#
# Input :  list of malware sample file names.
#        
#
# TODO: this should be modified to label all malware samples being trained.
#       so that file and trid id files do not have to be updated
#       during feature generation. This is a problem if multiprocessing
#       generation of feature sets is used as it will result in inconsistent
#       labelling of the file and trid id signatures between runs.
#         
#
# Output: av-file-id-labels.csv
#         row format = [file_type, id]
# 
#         av-trid-id-labels.csv
#         row format = [file_type, id]
#
# Author: Derek Chadwick
# Date  : 27/08/2016


import os
import re


def generate_file_id_labels(input_file):
    # Parse the file type list and convert to csv.
    fip = open(input_file, 'r')
    in_lines = fip.readlines()
    fop = open('data/av-file-id-labels.csv','w')
    fop.write('file_type,id\n')
    fop.write('unknown,0\n')
    
    #p1 = re.compile('Strength = (\d+) : (.+) \[(.*)\]') # Extract the 3 items of interest.
    out_lines = []
    row = ""
    counter = 0
    file_id_map = {}
    file_id_map['unknown'] = 0

    for idx, line in enumerate(in_lines): 
        line = line.rstrip().replace(',','')
        if line not in file_id_map.keys():
            counter += 1
            row = line + "," + str(counter) + "\n"
            file_id_map[line] = counter
            out_lines.append(row)


        if (idx % 1000) == 0: # print progress
            fop.writelines(out_lines)
            out_lines = []
            print('File type: {:s} - {:d}'.format(row.rstrip(),idx))
        

    if len(out_lines) > 0:
        fop.writelines(out_lines)
        out_lines = []

    fip.close()
    fop.close()

    print('Completed {:d} file IDs.'.format(counter))

    return


def generate_trid_id_labels(input_file):
    # Parse the file type list and convert to csv.
    fip = open(input_file, 'r')
    in_lines = fip.readlines()
    fop = open('data/av-trid-id-labels.csv','w')
    fop.write('file_type,id\n')
    fop.write('unknown,0\n')
    p1 = re.compile('.*(\d+\.\d+)\% (.+) \(\d+\/\d+\/\d+\)') # Extract the items of interest.
    out_lines = []
    row = ' '
    counter = 0
    file_id_map = {}
    file_id_map['unknown'] = 0

    for idx, line in enumerate(in_lines):
        m = p1.match(line)
        if m != None:
            percent = m.group(1)
            file_type = m.group(2).replace(',','')
            if file_type not in file_id_map.keys():
                counter += 1 
                row = file_type + ',' + str(counter) + '\n'
                file_id_map[file_type] = counter
                out_lines.append(row)


        if (idx % 1000) == 0: # print progress
            fop.writelines(out_lines)
            out_lines = []
            print('Filename: {:s} - {:d}'.format(row.rstrip(), idx))
        

    if len(out_lines) > 0:
        fop.writelines(out_lines)
        out_lines = []

    fip.close()
    fop.close()

    print('Completed {:d} trid IDs.'.format(counter))

    return


# Start of script.
if __name__ == "__main__":


    # TODO: add command line options to specify input and output file names.

    generate_file_id_labels('data/magic-reports-file-all-trains.txt')

    generate_trid_id_labels('data/magic-reports-trid-all-trains.txt')

# End of script.


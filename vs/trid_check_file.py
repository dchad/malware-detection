# trid_check_file.py
#
# Generate file/magic signatures for the malware samples
# that can be used to generate file type/id features.
# Uses the linux "file" utility and the TrID program
# to analyse each file and generate a report.
# These reports are then processed to generate
# file id and trid id databases for later use in
# the feature engineering phase.
#
# Outputs: <pid>-file-id.csv (four files on each run)
#          <pid>-trid-id.csv (four files on each run)
#
# Author: Derek Chadwick
# Date  : 01/09/2016

import os
import sys
import re
import subprocess as sub
from multiprocessing import Pool


def process_files(file_list):
    # Iterate over the file list and output the results from the "file" command.
    out_lines = []
    file_counter = 0
    pid = os.getpid()
    file_name = "data/" + str(pid) + "-file-id.csv"
    fop = open(file_name,'a')
    
    for idx, file_name in enumerate(file_list):
        file_name = file_name.rstrip() # remove the newlines or else !!!
        file_path =  ext_drive + file_name

        if (os.path.isfile(file_path)):
            #print("File: {:s}".format(file_path))
            signat = sub.check_output(["file","-b", file_path]) # Use the brief option, we do not need the file name.
            out_lines.append(signat)
        
        if (idx % 1000) == 0: # print progress
            fop.writelines(out_lines)
            out_lines = []
            print('{:s} - {:s} - {:d} - {:s}'.format(str(pid), file_name, idx, signat))
            
            
    if len(out_lines) > 0:
        fop.writelines(out_lines)
        out_lines = []    

    fop.close()
    
    return


def process_trids(file_list):
    # Iterate over the file list and output the results from TrID.
    out_lines = []
    high_score_line = ""
    file_counter = 0
    pid = os.getpid()
    file_name = "data/" + str(pid) + "-trid-id.csv"
    fop = open(file_name,'a')
    
    for idx, file_name in enumerate(file_list):
        file_name = file_name.rstrip() # remove the newlines or else !!!
        file_path1 =  ext_drive + file_name

        if (os.path.isfile(file_path1)):
            #print("File: {:s}".format(file_path1))
            signat = sub.check_output(["/opt/vs/trid", file_path1])
            components = signat.split('\n')
            for idx2, line in enumerate(components):
                if line.startswith("Collect"):
                    high_score_line = components[idx2 + 1] + "\n"
                    out_lines.append(high_score_line) # If we find a TrID signature the next line
                    break                             # contains the highest probability file type.
            
        if (idx % 1000) == 0: # print progress
            fop.writelines(out_lines)
            out_lines = []
            print('{:s} - {:s} - {:d} - {:s}'.format(str(pid), file_name, idx, high_score_line))
            
            
    if len(out_lines) > 0:
        fop.writelines(out_lines)
        out_lines = []                
     
    fop.close()
    
    return


def combine_magic_reports(out_file, file_pattern):
    # Concatenate the four report files into one file.
    fop = open(out_file,'w')
    p1 = re.compile(file_pattern) # This is the pattern for each file.
    file_list = os.listdir('data/')
    counter = 0
    
    for file_name in file_list:
        if p1.match(file_name):
            fip = open('data/' + file_name, 'r')
            in_lines = fip.readlines()
            fop.writelines(in_lines)
            counter += len(in_lines)
            fip.close()
            
    print('Completed combine of {:d} magic reports.'.format(counter))  
    
    fop.close()
    
    return


# Start of Script
if __name__ == "__main__":

    ext_drive_list = [ "/opt/vs/apt/", "/opt/vs/train1/", "/opt/vs/train2/", "/opt/vs/train3/", "/opt/vs/train4/"]

    #ext_drive = "/opt/vs/train1/"

    for idx, ext_drive in enumerate(ext_drive_list):
        tfiles = os.listdir(ext_drive)
        quart = len(tfiles)/4
        train1 = tfiles[:quart]
        train2 = tfiles[quart:(2*quart)]
        train3 = tfiles[(2*quart):(3*quart)]
        train4 = tfiles[(3*quart):]

        print("Files: {:d} - {:d} - {:d}".format(len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

        trains = [train1, train2, train3, train4]
        p = Pool(4)
        p.map(process_files, trains)

        print('Completed processing {:d} files.'.format(len(tfiles))) 

    combine_magic_reports('data/magic-reports-file-all-trains.txt', '\d{3,5}-file-id.csv')

    for idx, ext_drive in enumerate(ext_drive_list):
        tfiles = os.listdir(ext_drive)
        quart = len(tfiles)/4
        train1 = tfiles[:quart]
        train2 = tfiles[quart:(2*quart)]
        train3 = tfiles[(2*quart):(3*quart)]
        train4 = tfiles[(3*quart):]

        print("Files: {:d} - {:d} - {:d}".format(len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

        trains = [train1, train2, train3, train4]
        p = Pool(4)
        p.map(process_trids, trains)

        print('Completed processing {:d} files.'.format(len(tfiles)))
        
    combine_magic_reports('data/magic-reports-trid-all-trains.txt', '\d{3,5}-trid-id.csv')

# End of Script
    
    
    

        

# Convert ClamAV and Windows Defender reports to csv files.
#
# Input : Windows defender log files and ClamAV log files.
#
# Output: sorted-av-report.csv
#         row format = [file_name, malware_type]
#
# Author: Derek Chadwick
# Date  : 30/07/2016

import os
import sys
from csv import writer
import pandas as pd
import io # this is required as a compatability layer between 2.x and 3.x because 2.x cannot read utf-16 text files.



def process_clamav_report(vlines, outfile):
    counter = 0
    outlines = []
    for idx, line in enumerate(vlines):
        if line.startswith('---'): # we hit the scan summary at end of file.
            break
        else:
            line = line.rstrip() # get rid of newlines they are annoying
            line = line.replace('_', ' ').replace(':', ' ') # get rid of these things they are annoying
            tokens = line.split(' ')
            if len(tokens) > 2:
                malware_file_name = tokens[1]
                malware_type = tokens[2]
                outlines.append([malware_file_name, malware_type])
                counter += 1
                if (idx % 1000) == 0: # write out some lines
                    outfile.writerows(outlines)
                    outlines = []
                    print("Processed line number {:d} : {:s} -> {:s}.".format(idx, malware_file_name, malware_type))
            
    # Finish off.
    if (len(outlines) > 0):
        outfile.writerows(outlines)
        outlines = []
        
    print("Completed processing {:d} ClamAV lines.".format(counter))

    return


def process_defender_report(vlines, outfile):
    counter = 0
    outlines = []
    for idx, line in enumerate(vlines):
        if 'DETECTION' in line: # We have a malware detection line.
            line = line.rstrip() # get rid of newlines they are annoying
            #line = line.replace('_', ' ').replace(':', ' ') 
            tokens = line.split(' ')
            if len(tokens) > 2:
                temp_file_name = tokens[3]
                malware_type = tokens[2]
                temp_file_name = temp_file_name.replace('_',' ').replace('->',' ')
                path_tokens = temp_file_name.split()
                malware_file_name = path_tokens[1]
                outlines.append([malware_file_name, malware_type])
                counter += 1
                if (idx % 1000) == 0: # write out some lines
                    outfile.writerows(outlines)
                    outlines = []
                    print("Processed line number {:d} : {:s} -> {:s}.".format(idx, malware_file_name, malware_type))
        else:
            print("Skipping line number: {:d}".format(idx))
                
            
    # Finish off.
    if (len(outlines) > 0):
        outfile.writerows(outlines)
        outlines = []
        
    print("Completed processing {:d} Windows Defender lines.".format(counter))

    return


# Start of script execution

# TODO: add command line options to specify input and output file names.

# Load in the av report and convert to csv file.
file_name = sys.argv[1]


cols = ['filename','malware_type'] # write out the column names.


if file_name.endswith('.txt'):
    # Open the output csv for ClamAV file (filename format is vs00xxx.txt).
    vfr = open(file_name, 'r')
    vlines = vfr.readlines()
    
    print("Read {:d} lines from AV report {:s}".format(len(vlines), sys.argv[1]))
    
    fop = open('data/sorted-av-report-vs.csv', 'w')
    csv_wouter = writer(fop)
    csv_wouter.writerow(cols)
    process_clamav_report(vlines, csv_wouter)
    fop.close()
else:
    # Open the output csv for Windows Defender file (filename format is MPDetection-yyyymmdd-hhmmss.log).
    # NOTE: windows defender logs are UTF-16, so we have to use io module to open in Python 2.x
    #       AND specify UTF-16 as the text encoding, otherwise NOTHING happens and all is FAIL.
    #       Python 3.x does not have this problem.
    
    vfr = io.open(file_name, mode='r', encoding='utf-16')
    vlines = vfr.readlines()
    
    print("Read {:d} lines from AV report {:s}".format(len(vlines), sys.argv[1]))
    
    fop = open('data/sorted-av-report-wd.csv', 'w')
    csv_wouter = writer(fop)
    csv_wouter.writerow(cols)
    process_defender_report(vlines, csv_wouter)
    fop.close()
    

vfr.close()



# End of Script



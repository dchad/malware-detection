# feature_extraction_html.py
#
# Read a list of HTML files and count HTML tag occurrences.
#
#
# Input: list of HTML file names.
#        html-tags.txt
#
# Output: sorted-html-features.csv
#         row format = [ file_name, [list html tags...] ]
#
# Author: Derek Chadwick
# Date  : 05/09/2016
#
# TODO: all of the things


from multiprocessing import Pool
import os
from csv import writer
import numpy as np
import pandas as pd
import math
import scipy.misc
import array
import time as tm
import re




def get_html_tags(file_name):
    # Get the list of html tags.
    html_tags = []
    fip = open(file_name, 'r')
    for tag in lines:
        tag = tag.rstrip()
        html_tags.append(tag)
        
        
    return html_tags


def count_html_tags(content, tag_list, klen):
    
    tag_values = [0] * klen
    
    for row in content:
        for i in range(klen):
            if tag_list[i] in row:
                tag_values[i] += 1
                break
                
    return tag_values



def extract_html_features(multi_parameters):
    # 1. Get the feature file and tag list file
    # 2. Create an array of tag values.
    # 3. Iterate throught the html file list and count the occurrence of the tags in each file.

    pid = os.getpid()
    feature_file = 'data/' + str(pid) + "-" + multi_parameters.out_file  
    tag_list = multi_parameters.token_list
    html_files = multi_parameters.file_list
    
    print('Process id: {:d} - Feature file: {:s}'.format(pid, feature_file))

    tlen = len(tag_list)
    ftot = len(html_files)
    
    feature_counts = []
    with open(feature_file, 'w') as f:

        fw = writer(f)
        fw.writerow(['file_name'] + tag_list)
        
        for idx, fname in enumerate(html_files):
            
            fasm = open(fname, 'r')
            content = fasm.readlines()
            fasm.close()

            #print("Debug in -> {:s}".format(fname))
            
            fname = fname[fname.find("_")+1:] 
            # Remove VirusShare_ and path from the start of the file name.
            
            keyword_vals = count_html_tags(content, tag_list, tlen)
            
            feature_counts.append([fname] + keyword_vals)
            
            # Writing rows after every 10 files processed
            if (idx+1) % 100 == 0:
                print("{:d} - {:d} of {:d} files processed.".format(pid, idx + 1, ftot))
                fw.writerows(feature_counts)
                feature_counts = []
                
            #print("Debug out -> {:s}".format(fname))

        # Writing remaining features
        if len(feature_counts) > 0:
            fw.writerows(feature_counts)
            feature_counts = []

    print("{:d} Completed processing {:d} HTML files.".format(pid, ftot))
                      
    return



class Multi_Params(object):
    def __init__(self, outfile="", tokenlist="", filelist=[]):
        self.out_file = outfile
        self.token_list = tokenlist
        self.file_list = filelist
        
        
        
        
# Start of Script

# we have a problem with the file names in train3 that has to be fixed...
# see function train3_binary_files_fix() in feature-extraction-validation.ipynb
target_dir = "/opt/vs/train3/"
out_file = "sorted-html-features-vs263.csv"
html_files = 'data/html-file-list-vs263.txt'

#target_dir = "/opt/vs/train4/"
#out_file = "sorted-html-features-vs264.csv"
#html_files = 'data/html-file-list-vs264.txt'

# Get a list of HTML files in the file set.
html_list = []
fip = open(html_files, 'r')
in_lines = fip.readlines()
for line in in_lines:
    line = line.rstrip()
    html_list.append(target_dir + "VirusShare_" + line) # Reattach file name to canonical path.
    
    
# Get a list of HTML tags.
tag_list = []
fip = open('data/html-tags.txt', 'r')
in_lines = fip.readlines()
for line in in_lines:
    #line = line.rstrip()
    line = line[:line.find('>')] # Remove the tag close bracket, we do not want it.
    if '...' in line: # Check for the comment tag.
        line = '<!--'
    tag_list.append(line)
    print("Got tag: {:s}".format(line))
    

print("Got {:d} HTML files.".format(len(html_list)))

mp1 = Multi_Params(out_file, tag_list, html_list)

extract_html_features(mp1)


# End of Script

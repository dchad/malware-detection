# feature_extraction_entropy.ph
#
# Calculate Shannon's Entropy and file size for each malware sample.
#
# Reference: https://en.wikipedia.org/wiki/Entropy_(information_theory)
#
# Inputs : List of files to process.
#
# Outputs: xxxx-entropy-features-bin.csv (4 x feature files)
#
#          Combined into one file:
#        
#          sorted-entropy-features.csv
#          row format = [file_name, entropy, file_size]
# 
# Author: Derek Chadwick
# Date  : 03/08/2016

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
import subprocess as sub



def calculate_entropy(byte_counts, total):
    
    entropy = 0.0

    for count in byte_counts:
        # If no bytes of this value were seen in the value, it doesn't affect
        # the entropy of the file.
        if count == 0:
            continue
        # p is the probability of seeing this byte in the file, as a floating-point number
        p = 1.0 * count / total
        entropy -= p * math.log(p, 256)
    

    return entropy


def entropy_counter(byte_code, code_length):
    #return 0
    byte_counts = [0] * 256
    #code_length = len(byte_code)
    
    # Something horrible is happening with large file sizes (>50MB)!!!
    # Two processes hang on vs264 sample set. Does not happen on other
    # virusshare sample sets.
    #if code_length > 50000000:
    #   code_length = 50000000
       
    for i in range(code_length):
        byte_counts[int(byte_code[i])] += 1
        
    entropy = calculate_entropy(byte_counts, code_length)

    return entropy


def sort_and_save_entropy_feature_file():
    entropys = pd.read_csv('data/entropy-features.csv')
    # DataFrame.sort() is deprecated, but this is an old version of pandas, does not have sort_values().
    sorted_entropys = entropys.sort('file_name')
    sorted_entropys.to_csv('data/sorted-entropy-features.csv', index=False)
    sorted_entropys.head(20)
    
    return


def combine_entropy_files():
    # Function to combine the newly generated entropy files into one file:
    # 1. list data directory
    # 2. For each file in file list that matches (\d\d\d\d-entropy-features.csv)
    # 3. Trim the filenames if necessary (should remove VirusShare_  prefix).
    # 4. Concatenate the unsorted packer id feature files.
    # 5. Sort and write to data/sorted-packer-id-features.csv
    fop = open('data/entropy-features.csv','w')
    fop.write('file_name,entropy,file_size\n')
    p1 = re.compile('\d{3,5}-entropy-features-bin.csv') # This is the PID prefix for each file.
    file_list = os.listdir('data/')
    counter = 0
    for file_name in file_list:
        if p1.match(file_name):
            fip = open('data/' + file_name, 'r')
            in_lines = fip.readlines()
            fop.writelines(in_lines)
            counter += len(in_lines)
            fip.close()
            
    print('Completed combine of {:d} entropy features.'.format(counter))  
    
    fop.close()
    
    sort_and_save_entropy_feature_file()
    
    return


# feature extraction for the binary files

def extract_binary_features(tfiles):
    #byte_files = [i for i in tfiles if '.bytes' in i]
    ftot = len(tfiles)
    
    pid = os.getpid()
    print("Process id: {:d}".format(pid))
    feature_file = 'data/' + str(pid) + '-entropy-features-bin.csv' # entropy, file size, ngrams...   
    print("Feature file: {:s}".format(feature_file))
    
    feature_counts = []
    with open(feature_file, 'w') as f:
        # Write the column names for the csv file
        fw = writer(f)
        # Do this when combining the files.
        #colnames = ['file_name'] + ['entropy'] + ['file_size'] 
        #fw.writerow(colnames)
        
        # Now iterate through the file list and extract the features from each file.
        for idx, fname in enumerate(tfiles):
            fasm = open(ext_drive + fname, 'rb')
            filesize = os.path.getsize(ext_drive + fname)
            in_bytes = fasm.read()
            
            # TODO: Do ngram extraction
            # First do entropy calculations and filesize
            # Convert the input array into a byte array to prevent type errors
            # in entropy counter function.
            in_bytes = bytearray(in_bytes)
            #print("Type = {:s}").format(type(in_bytes))
            entropy = entropy_counter(in_bytes, filesize)
            
            count_vals = [entropy, filesize]
            
            feature_counts.append([fname[fname.find('_')+1:]] + count_vals)   
            
            fasm.close()
            
            print("{:d} - {:d} of {:d} files processed.".format(pid, idx + 1, ftot))
            
            # Print progress
            if (idx + 1) % 1000 == 0:
                print("{:d} - {:d} of {:d} files processed.".format(pid, idx + 1, ftot))
                fw.writerows(feature_counts)
                feature_counts = []
                
        # Write remaining files
        if len(feature_counts) > 0:
            fw.writerows(feature_counts)
            feature_counts = []

    print("Completed processing {:d} rows for feature file {:s}".format(ftot,feature_file))
        
    return
    
    
# Start of Script

# Divide the train files into four groups for multiprocessing.

# TODO: add command line arguments to specify file names.

#ext_drive = '/opt/vs/train1/'
#ext_drive = '/opt/vs/train2/'
#ext_drive = '/opt/vs/train3/'
ext_drive = '/opt/vs/train4/'
#ext_drive = '/opt/vs/apt/'
#ext_drive = '/opt/vs/train/'


tfiles = os.listdir(ext_drive)
quart = len(tfiles)/4
train1 = tfiles[:quart]
train2 = tfiles[quart:(2*quart)]
train3 = tfiles[(2*quart):(3*quart)]
train4 = tfiles[(3*quart):]
print("Files: {:d} - {:d} - {:d}".format(len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))
trains = [train1, train2, train3, train4]
#p = Pool(4)
#p.map(extract_binary_features, trains)

print("Completed Entropy Generation for {:d} Files.".format(len(tfiles)))

#combine_entropy_files()

# End of Script
    
# TEST: problem with train4 (vs264), 2 of the 4 processes would never finish, cause unknown!!!

# Cause: memory exhaustion with no error/exception messages.
# Solution: Run as a single process.



fip1 = open('data/3019-entropy-features-bin.csv','r')
fip2 = open('data/3020-entropy-features-bin.csv','r')
fip3 = open('data/3021-entropy-features-bin.csv','r')
fip4 = open('data/3022-entropy-features-bin.csv','r')

lines1 = fip1.readlines()
lines2 = fip2.readlines()
lines3 = fip3.readlines()
lines4 = fip4.readlines()

file_list = []
counter = 0

for line in lines1:
    tokens = line.split(',')
    if len(tokens) > 1:
        file_name = "VirusShare_" + tokens[0]
        file_list.append(file_name)
        counter += 1
    
for line in lines2:
    tokens = line.split(',')
    if len(tokens) > 1:
        file_name = "VirusShare_" + tokens[0]
        file_list.append(file_name)
        counter += 1
    
for line in lines3:
    tokens = line.split(',')
    if len(tokens) > 1:
        file_name = "VirusShare_" + tokens[0]
        file_list.append(file_name)
        counter += 1
    
for line in lines4:
    tokens = line.split(',')
    if len(tokens) > 1:
        file_name = "VirusShare_" + tokens[0]
        file_list.append(file_name)
        counter += 1
    
    
processed_file_count = counter

print("Read {:d} file names.".format(counter))

unprocessed_file_list = []
counter = 0

for idx, file_name in enumerate(tfiles):
    if file_name not in file_list:
        unprocessed_file_list.append(file_name)
        counter += 1
        
    if (idx % 1000) == 0:
        print("{:d} - filename: {:s} - counter: {:d}".format(idx, file_name, counter))


unprocessed_file_count = counter

print("Found {:d} unprocessed files.".format(counter))

print("Total files: {:d}".format(processed_file_count + unprocessed_file_count))

#fop = open("data/unprocessed-files.txt","w")
#fop.writelines(unprocessed_file_list)
#fop.close()

extract_binary_features(unprocessed_file_list)

combine_entropy_files()


fip1.close()
fip2.close()
fip3.close()
fip4.close()



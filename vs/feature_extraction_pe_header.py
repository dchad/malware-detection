# feature_extraction_pe_header.py
#
# Read a list of PE/COFF header files dumped
# by objdump and extract feature sets from them.
# Features include PE section names, imported DLL names,
# imported function names, exported function names etc.
#
# Input : pe-header-tokens.csv 
#         row format = [token_name, count]
#         (Contains the section names, imported DLL names etc.)
#
#         and
#
#         A list of PE/COFF header files dumped by objdump.
#
# Output: sorted-pe-header-features.csv
#         row format = [file_name, [keyword list...]]
#
#
#
# Author: Derek Chadwick
# Date  : 13/09/2016
#
# TODO: optimise and many many things

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

field_list = [ "Characteristics","Time/Date","Magic","MajorLinkerVersion","MinorLinkerVersion",
"SizeOfCode","SizeOfInitializedData","SizeOfUninitializedData","AddressOfEntryPoint",
"BaseOfCode","BaseOfData","ImageBase","SectionAlignment","FileAlignment",
"MajorOSystemVersion","MinorOSystemVersion","MajorImageVersion","MinorImageVersion",
"MajorSubsystemVersion","MinorSubsystemVersion","Win32Version",
"SizeOfImage","SizeOfHeaders","CheckSum","Subsystem","DllCharacteristics","SizeOfStackReserve",
"SizeOfStackCommit","SizeOfHeapReserve","SizeOfHeapCommit","LoaderFlags","NumberOfRvaAndSizes" ]

field_list_len = len(field_list)

ptime = re.compile("Time/Date\s+(.+)") # Time/Date pattern for PE Header field.


def reduce_column_names(column_names_file):
    # Reduce the number of column names, there are just too many.

    colf = open(column_names_file, 'r')
    all_column_names = []
    column_lines = colf.readlines()
    for line in column_lines:
        # lets try to reduce the vast number of functions.
        func = line.rstrip()
        if func.startswith('sub') or func.startswith('loc') or func.startswith('unk'):
            func = func[:5] 
        elif func.startswith('eax+') or func.startswith('ebx+') or func.startswith('ecx+') or func.startswith('edx+'):
            func = func[:5]
        elif func.startswith('edi+') or func.startswith('esi+'):
            func = func[:5]
        elif func.startswith('byte_') or func.startswith('word_') or func.startswith('off_'):
            func = func[:5]
        elif func.startswith('_'): 
            func = func[:5]
        
        if len(func) > 16:
            func = func[:16]
        if len(func) < 1:
            continue

        if func not in all_column_names:
            all_column_names.append(func)


    col_names_len = len(all_column_names)
    
    colf.close()

    print("Column Names Length: {:d}".format(col_names_len))

    return all_column_names



def get_field_values(header_lines, file_name):

    field_vals = [0] * field_list_len
    header_len = len(header_lines)
    
    if header_len < 44 or header_len > 1000000: # We have a bad header file, just return all zeroes.
        print("Bad Header: {:s} Len: {:d}".format(file_name, header_len))
        return field_vals
    
    for idx1 in range(0,44): # The PE header fields are the first 44 lines of the file.
        
        line = header_lines[idx1].rstrip()
        tokens = line.split()
        
        for idx2, field_name in enumerate(field_list):
            
            if field_name in tokens:
                if field_name.startswith("Time"):
                    time_match = ptime.match(field_name)
                    if time_match != None:   
                        time_str = time_match.group(1) 
                        time_s = tm.strptime(time_str, "%a %b %d %H:%M:%S %Y") # Convert time string to epoch int.
                        time_epoch = tm.mktime(time_s)
                    else:
                        time_epoch = 0
                        
                    field_vals[idx2] = time_epoch

                elif len(tokens) > 1:
                    # We are picking up some negative values and they are bad and must be eradicated.
                    fval = int(tokens[1], 16) # Convert the hex value of the field to int.
                    if fval < 0: # Nasty negative.
                        fval = abs(fval)
                        
                    field_vals[idx2] = fval 
                
    return field_vals
                
                
def count_header_keywords(asm_code, keywords, klen, file_name):
    
    keywords_values = [0] * klen
    
    header_len = len(asm_code)
    
    if header_len < 44 or header_len > 1000000: # We have a bad header file, just return all zeroes.
        print("Bad Header: {:s} Len: {:d}".format(file_name, header_len))
        return keywords_values
    
    for row in asm_code:
        # Now demangle C++ names, they are annoying.
        row = row.replace('@','').replace('$','').replace('?','') #.replace('\t','')
        for i in range(klen):
            if keywords[i] in row:
                keywords_values[i] += 1
                break
                
    return keywords_values


def extract_header_features(multi_parameters):
    # 1. Get the feature file and token/keyword file names
    # 2. Create an array of token/keyword values.
    # 3. Iterate throught the PE header file list and counter the occurrence of the keywords in each file.

    pid = os.getpid()
    feature_file = 'data/' + str(pid) + "-" + multi_parameters.out_file  
    token_file = 'data/' + multi_parameters.token_file
    
    print('Process id: {:d} - Feature file: {:s} - Keyword file: {:s}'.format(pid, feature_file, token_file))

    hdr_pd = pd.read_csv(token_file, na_filter=False)
    tokens = list(hdr_pd['token_name'])
    tlen = len(tokens)

    

    for idx, token in enumerate(tokens): # Clamp the token name length and demangle C++ names, they are annoying.
        # token = token.replace('@','').replace('$','').replace('?','')
        # already done in generate_pe_header_tokens.py
        # print("Token: {:s}".format(token))
        ##################################################################################
        # NOTE: Hilarious discovery, if any token/keyword names are == "NULL" then
        # pandas will convert them to a float == 0.0
        # The default NA list for pandas includes strings such as NULL, NA, NAN etc,
        # so set na_filter to False or bad shit happens.
        ##################################################################################
        if len(token) > 32:
            tokens[idx] = token[:32]
        else:
            tokens[idx] = token
            

    asm_files = [i for i in multi_parameters.file_list if '.pe.txt' in i]
    ftot = len(asm_files)

    print("{:d} - Got {:d} PE Header files.".format(pid, ftot))
    
    feature_counts = []
    with open(feature_file, 'w') as f:

        fw = writer(f)
        
        for idx, fname in enumerate(asm_files):
            
            fasm = open(ext_drive + fname, 'r')
            content = fasm.readlines()
            fasm.close()

            #print("Debug in -> {:s}".format(fname))
            
            fname = fname[fname.find("_")+1:] # Remove VirusShare_ from the start of the file name.
            
            field_vals = get_field_values(content, fname)
            keyword_vals = count_header_keywords(content, tokens, tlen, fname)
            
            feature_counts.append([fname[0:fname.find('.pe.txt')]] + field_vals + keyword_vals)   
            
            # Writing rows after every 10 files processed
            if (idx+1) % 1000 == 0:
                print("{:d} - {:d} of {:d} files processed.".format(pid, idx + 1, ftot))
                fw.writerows(feature_counts)
                feature_counts = []
                
            #print("Debug out -> {:s}".format(fname))

        # Writing remaining features
        if len(feature_counts) > 0:
            fw.writerows(feature_counts)
            feature_counts = []

    print("{:d} Completed processing {:d} PE header files.".format(pid, ftot))
                      
    return


def combine_feature_files(feature_file_name, token_file):
    # Function to combine the newly generated PE header feature files into one file:
    # 1. list data directory
    # 2. For each file in file list that matches (\d\d\d\d-pe-header-features.csv)
    # 3. Trim the filenames if necessary (should remove VirusShare_  prefix).
    # 4. Concatenate the unsorted pe header feature files.
    # 5. Sort and write to data/sorted-pe-header-features.csv
    
    hdr_pd = pd.read_csv('data/' + token_file, na_filter=False)
    tokens = list(hdr_pd['token_name'])
    for idx, token in enumerate(tokens): # Clamp the token name length and demangle C++ names, they are annoying.
        # token = token.replace('@','').replace('$','').replace('?','')
        # already done in generate_pe_header_tokens.py
        if len(token) > 32:
            tokens[idx] = token[:32]
        else:
            tokens[idx] = token
        


    fop = open('data/' + feature_file_name,'w')
    colnames = "file_name," + ",".join(field_list) + "," + ",".join(tokens) + "\n"
    #print("Column names: {:s}".format(colnames))
    fop.write(colnames)                    

    p1 = re.compile('\d{3,5}-' + feature_file_name) # This is the PID prefix for each file.
    file_list = os.listdir('data/')
    #TEMP FIX: file_list = os.listdir('/opt/vs/')
    counter = 0
    
    for file_name in file_list:
        if p1.match(file_name):
            fip = open('data/' + file_name, 'r')
            in_lines = fip.readlines()
            fop.writelines(in_lines)
            counter += len(in_lines)
            fip.close()
            
    
    fop.close()
    
    # These files are too big for pandas without at least 16GB of memory, have to reduce
    # the feature set before sorting and training.
    #features = pd.read_csv('data/' + feature_file_name)
    # DataFrame.sort() is deprecated, but this is an old version of pandas, does not have sort_values().
    #sorted_features = features.sort('file_name')
    #sorted_features.to_csv('data/sorted-' + feature_file_name, index=False)
    
    print('Completed combine of {:d} PE header file features.'.format(counter))  
    
    return



def validate_feature_set(feature_set_file_name, feature_set_len):
    fip = open(feature_set_file_name, 'r')
    fop = open("data/pe-header-errors.txt", 'w')
    feature_count = 0
    error_count = 0

    for line in fip:
        line = line.rstrip()
        tokens = line.split(',')
        feature_count = len(tokens)
        if feature_count != feature_set_len:
            if ((error_count + 1) % 10000) == 0:
                print("Feature counts inconsistent: {:d} {:d}".format(feature_count, feature_set_len))
            error_count += 1
            fop.write(str(feature_count) + " : " + line[:128] + '\n')


    fip.close()
    fop.close()

    print("Feature set validation: {:d} errors.".format(error_count))

    return





class Multi_Params(object):
    def __init__(self, outfile="", tokenfile="", fieldnames=[], filelist=[]):
        self.out_file = outfile
        self.token_file = tokenfile
        self.field_names = fieldnames
        self.file_list = filelist
        

# Start of script.
if __name__ == "__main__":

    # TODO: add command line arguments to specify file names.

    header_field_names = 'pe-coff-header-field-names.txt'


    #########################################################
    # NOTE: Clean the header token names before running feature
    #       extraction, the token names have non-ascii crap
    #       and negative values in them!
    #       vs252 and vs263 and vs264
    #########################################################

    out_file = 'pe-header-features-vs252.csv'
    token_file = 'pe-header-tokens-vs252.csv'
    ext_drive = '/opt/vs/train2hdr/'


    #out_file = 'pe-header-features-vs263.csv'
    #token_file = 'pe-header-tokens-vs263.csv'
    #ext_drive = '/opt/vs/train3hdr/'


    #out_file = 'pe-header-features-apt.csv'
    #token_file = 'pe-header-tokens-apt.csv'
    #ext_drive = '/opt/vs/apthdr/'




    tfiles = os.listdir(ext_drive)
                          
    # Divide the train files into four groups for multiprocessing.

    quart = len(tfiles)/4
    train1 = tfiles[:quart]
    train2 = tfiles[quart:(2*quart)]
    train3 = tfiles[(2*quart):(3*quart)]
    train4 = tfiles[(3*quart):]

    print("Files: {:d} - {:d} - {:d}".format(len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

    mp1 = Multi_Params(out_file, token_file, header_field_names, train1)
    mp2 = Multi_Params(out_file, token_file, header_field_names, train2)
    mp3 = Multi_Params(out_file, token_file, header_field_names, train3)
    mp4 = Multi_Params(out_file, token_file, header_field_names, train4)

    trains = [mp1, mp2, mp3, mp4]
    p = Pool(4)
    p.map(extract_header_features, trains)

    combine_feature_files(out_file, token_file)

    # Debug for infinite loop in train set 2.
    # problem is caused by file: VirusShare_143b02a7ece02e5efb02668fd0642ba4.pe.txt
    # what to do about this???
    # REMOVE THE FILE FROM THE TRAINING DIRECTORY!

    #print("Train1: {:s}".format(train1[0]))
    #print("Train2: {:s}".format(train2[0]))
    #print("Train3: {:s}".format(train3[0]))
    #print("Train4: {:s}".format(train4[0]))

    #extract_header_features(mp2)


# End of script.

# Generate packer id values for PE files.
#
# Inputs: av-packer-id-labels.csv (scalar labels for PE packer types.)
#         userdb-sans.txt (PEid.exe PE packer database.)
#
# Output: xxxx-sorted-packer-id-features.csv ( 4 x feature files )
#         row format = [file_name, packer_name, packer_id, valid_pe, is_packed]
#
#         Combined into one feature file:
#         sorted-packer-id-features.csv
#         row format = [file_name, packer_name, packer_id, valid_pe, is_packed]
#
#
# Author: Derek Chadwick
# Date  : 04/08/2016



from multiprocessing import Pool
import os
import peutils
import pefile
import sys
import re
import pandas as pd




def load_packer_id_map():
    # Load the packer ID scalar labels and create a map. There are a lot of duplicate names so the total is less than
    # the number of packers listed in the signature db.
    packer_id_map = {}

    counter = 0
    fip = open('data/av-packer-id-labels.csv','r')
    in_lines = fip.readlines()
    for idx in range(1,len(in_lines)):
        tokens = in_lines[idx].split(',')
        packer_name = tokens[0]
        if packer_name not in packer_id_map.keys():
            packer_id_map[packer_name] = int(tokens[1])
            counter += 1

    fip.close()
    print('Completed {:d} packer IDs.'.format(counter))
    
    return packer_id_map




def sort_and_save_packer_id_feature_file():
    # Load in the combined feature files, sort and save.
    # NOTE: add a file name argument so the final filename can be
    #       specified during runs on multiple datasets.
    
    packers = pd.read_csv('data/packer-id-features.csv')
    # DataFrame.sort() is deprecated, but this is an old version of pandas, does not have sort_values().
    sorted_packers = packers.sort('file_name')
    sorted_packers.to_csv('data/sorted-packer-id-features.csv', index=False)
    sorted_packers.head(20)
    
    return


def combine_packer_id_files():
    # Function to combine the four packer id files in one file
    # 1. list data directory
    # 2. For each file in file list that matches (\d\d\d\d-packer-id-features.csv)
    # 3. Trim the filenames if necessary (should remove VirusShare_  prefix).
    # 4. Concatenate the unsorted packer id feature files.
    # 5. Sort and write to data/sorted-packer-id-features.csv
    # NOTE: add a file name argument so the final filename can be
    #       specified during runs on multiple datasets.
    
    fop = open('data/packer-id-features.csv','w')
    fop.write('file_name,packer_name,packer_id,valid_pe,is_packed\n')
    p1 = re.compile('\d{3,5}-sorted-packer-id-features.csv') # This is the PID prefix for each file.
    file_list = os.listdir('data/')
    counter = 0
    
    for file_name in file_list:
        if p1.match(file_name):
            fip = open('data/' + file_name, 'r')
            in_lines = fip.readlines()
            #if counter > 0:
            #    in_lines = in_lines[1:] # skip the column header row
            fop.writelines(in_lines)
            counter += len(in_lines)
            fip.close()
            
    print('Completed combine of {:d} packer ID features.'.format(counter))  
    
    fop.close()
    
    sort_and_save_packer_id_feature_file()
    
    return

    


def generate_sample_packer_id(file_list):
    # Generate scalar packer IDs for each sample.
    pid = os.getpid()
    file_name = "data/" + str(pid) + "-sorted-packer-id-features.csv"
    fop = open(file_name,'w')
    #fop.write('file_name,packer_type,label,is_valid,is_packed\n') put column headers in during the combine stage.
    out_lines = []
    packer_id_map = load_packer_id_map()
    signatures = peutils.SignatureDatabase('data/userdb-sans.txt')
    non_pe_counter = 0
    pe_file_counter = 0
    exception_counter = 0
    signat = 'unknown'
    error_str = 'none'
    
    for idx, file_name in enumerate(file_list):
        tokens = file_name.split('_')
        truncated_file_name = tokens[1] # remove the VirusShare_ prefix from the filename.
        matches = None
        packer_id = 0
        is_valid = 0
        is_packed = 0
        
        try:
            pe = pefile.PE(ext_drive + file_name, fast_load=True)
            pe_file_counter += 1
            #matches = signatures.match_all(pe, ep_only = True)
            is_valid = 1
            
            try:
                                
                if peutils.is_probably_packed(pe): # NOTE: peutils.is_valid() has not been implemented yet.
                    #is_valid = 1
                    is_packed = 1
                    
                matches = signatures.match(pe, ep_only = True)       
                signat = matches[0]
                if (signat in packer_id_map.keys()):
                    packer_id = packer_id_map[signat]
                else:
                    packer_id = 0
                
                #signat = signat.replace(',','') # remove commas or they will cause an error when loading dataframes.
                # NOTE: If the signature database has commas in the packer name then remove them or they will
                #       cause problems later on when loading the dataframes.
                row = truncated_file_name + "," + signat + "," + str(packer_id) + "," + str(is_valid) + "," + str(is_packed) + "\n"
                
            except:
                signat = ",unknown,0," + str(is_valid) + "," + str(is_packed) + "\n"
                row = truncated_file_name + signat
                    
            
            pe.close()
        except Exception as e:
            error_str = str(e)
            non_pe_counter += 1
            error_str = error_str.replace(',','') # remove commas or they will cause an error when loading dataframes.
            signat = "," + error_str + ",0,0,0\n"
            row = truncated_file_name + signat
       
    
        out_lines.append(row)
        
        if (idx % 1000) == 0: # print progress
            fop.writelines(out_lines)
            out_lines = []
            print('{:s} - {:s} - {:d} - {:s}'.format(str(pid),truncated_file_name,idx,signat))


    if len(out_lines) > 0:
        fop.writelines(out_lines)
        out_lines = []

    fop.close()

    print('{:s} - Completed {:d} non PE files and {:d} PE files.'.format(str(pid), non_pe_counter, pe_file_counter))
    
    return


    
# Start of script

# TODO: add command line arguments to specify input files.

#ext_drive = '/opt/vs/train1/'
#ext_drive = '/opt/vs/train2/'
#ext_drive = '/opt/vs/train3/'
ext_drive = '/opt/vs/train4/'
#ext_drive = '/opt/vs/apt/'

tfiles = os.listdir(ext_drive)
quart = len(tfiles)/4
train1 = tfiles[:quart]
train2 = tfiles[quart:(2*quart)]
train3 = tfiles[(2*quart):(3*quart)]
train4 = tfiles[(3*quart):]

print("Files({:s}): {:d} - {:d} - {:d}".format(ext_drive, len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

trains = [train1, train2, train3, train4]
p = Pool(4)
p.map(generate_sample_packer_id, trains)

print('Completed processing {:d} files in {:s}.'.format(len(tfiles), ext_drive))

combine_packer_id_files()

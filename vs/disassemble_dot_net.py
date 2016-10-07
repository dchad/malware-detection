# disassemble_dot_net.py
#
# Performs two functions:
# 1. Generates of list of unpacked PE binary files for input to the second function.
# 2. Reads a list of unpacked .NET files and uses ildisasm.exe to disassemble
#    the CIL code.
#
# This has to run on a Windows VM as I cannot get Visual Studio 2015 to install
# using Wine.
#
# Input : unpacked_file_list.txt
#
# or
#
# Input : sorted-packer-id-features.csv
#         row format = [file_name, packer_name, packer_id, valid_pe, is_packed]
#
#         sorted-file-id-features.csv
#         row format = [file_name, file_type, file_id]
#
#         sorted-trid-id-features.csv
#         row format = [file_name, file_type, percentage, file_id]
#
# Output: assembler files [input_binary_filename.asm]
#         PE header files [input_binary_filename.txt]
#
# or
#
# Output: unpacked_file_list.txt
#
# Author: Derek Chadwick
# Date  : 01/10/2016


from multiprocessing import Pool
from optparse import OptionParser
import subprocess as sub
import os
import sys
import pandas as pd


def write_dot_net_file_list(packer_id_feature_file, dot_net_list_file_name):
    # Load the malware packer id features sets from the sample set.
    packer_id_features = pd.read_csv(packer_id_feature_file)
    unpacked_files = packer_id_features[packer_id_features['is_packed'] == 0]
    unpacked_pe_files = unpacked_files[unpacked_files['valid_pe'] == 1]
    
    fop = open(dot_net_list_file_name, 'w')
    counter = 0
    
    for idx, file_name in enumerate(unpacked_pe_files['file_name']):
        fdesc = unpacked_pe_files.iloc[idx,1]
        if ".NET" in fdesc: 
            full_name = "VirusShare_" + file_name + "\n"
            fop.write(full_name)
            counter += 1
        else:
            continue

    print("Wrote {:d} .NET filenames.".format(counter))

    fop.close()
    
    return


def get_dot_net_file_list(packer_id_feature_file, file_id_feature_file, trid_id_feature_file):
    # Load the malware packer id features and file id features from the sample set.
    packer_id_features = pd.read_csv(packer_id_feature_file)
    file_id_features = pd.read_csv(file_id_feature_file)
    trid_id_features = pd.read_csv(trid_id_feature_file)
    
    # Get a list of unpacked PE files that are not .NET CIL format and not 64 bit.
    # IDA Pro cannot disassemble .NET files, have to use Ildisasm.exe in Visual Studio,
    # and free version will not disassemble 64 bit, use objdump instead.
    unpacked_files = packer_id_features[packer_id_features['is_packed'] == 0]
    unpacked_pe_files = unpacked_files[unpacked_files['valid_pe'] == 1]
    dot_net_list = []
    dot_net_counter = 0
    
    # Get the trid and file rows that are for unpacked PE files.
    trids = trid_id_features[trid_id_features['file_name'].isin(unpacked_pe_files['file_name'])]
    fids = file_id_features[file_id_features['file_name'].isin(unpacked_pe_files['file_name'])]
    
    # Iterate over the unpacked PE file list and check if each is a .NET file.
    # If not a .NET file then add to file list.
    pe_names_list = unpacked_pe_files['file_name']
    
    for idx, file_name in enumerate(pe_names_list):
        trid_name = trids.iloc[idx, 1]
        fid_name = fids.iloc[idx, 1]
        trid_name = trid_name.lower()
        fid_name = fid_name.lower()
        
        if trid_name.find('.net') > -1 or fid_name.find('.net') > -1:
            print('Found: {:s} - {:s}'.format(trid_name, fid_name))
        else:
            continue
            
        dot_net_list.append(file_name)
        dot_net_counter += 1
    
    file_list = []
    write_list = []
    counter = 0
    
    # Iterate over the file list and prepend the full file name.
    for file_name in dot_net_list:
        full_name = "VirusShare_" + file_name
        file_list.append(full_name)
        write_list.append(full_name + "\n")
        counter += 1

    if (len(file_list) > 0):   
        fop = open('data/temp-pe-dot-net-list.txt','w')
        fop.writelines(write_list)
        fop.close()
    
    print("Got {:d} .NET files.".format(dot_net_counter))

    return file_list



def disassemble_dot_net_binaries(file_list):
    counter = 0
    disassed = 0
    error_count = 0
    pid = os.getpid()
    log_file = "data/" + str(pid) + '-pe-disass-log.net.txt'
    
    smsg = "{:d} Disassembling {:d} binary .NET files.".format(pid, len(file_list))
    print(smsg)
    flog = open(log_file, 'w')
    flog.write(smsg + "\n")
    
    for file_name in file_list:
        file_path = file_name.rstrip() # remove the newlines or else !!!
        asm_file_name = file_path + ".pe.net.asm"
        hdr_file_name = file_path + ".pe.net.txt"
            
        if (os.path.isfile(file_path)):
            fop = open(asm_file_name, 'w')
            # Dump the assembly code listing.
            sub.call(["ildisasm.exe", file_path], stdout=fop)
            disassed += 1
            fop.close
        else:
            error_count += 1
           
        counter += 1
        
        if (counter % 10) == 0: # print progress
            smsg = '{:d} Disassembled: {:d} - {:s}'.format(pid, counter, file_name)
            print(smsg)
            flog.write(smsg + "\n")    
 

    smsg = "{:d} Disassembled {:d} .NET binaries with {:d} file path errors.".format(pid, disassed, error_count)
    print(smsg)
    flog.write(smsg + "\n")
    flog.close()
    
    return



# Start of Script.


# End of Script.


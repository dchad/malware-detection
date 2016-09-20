# disassemble_elf.py
#
# Performs two functions:
# 1. Generates of list of ELF binary files for input to the second function.
# 2. Reads a list of ELF files and uses readelf to extract header 
#    information from each binary and objdump to generate assembly code
#    of the binary.
#
# Input : elf_file_list.txt
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
# Output: assembler files [input_binary_filename.elf.asm]
#         ELF header files [input_binary_filename.elf.txt]
#
# or
#
# Output: elf_file_list.txt
#
# Author: Derek Chadwick
# Date  : 05/09/2016


from optparse import OptionParser
import subprocess as sub
import os
import sys
import pandas as pd


def get_elf_file_list(ext_drive, packer_id_feature_file, file_id_feature_file, trid_id_feature_file):
    # Load the malware packer id features and file id features from the sample set.
    packer_id_features = pd.read_csv(packer_id_feature_file)
    file_id_features = pd.read_csv(file_id_feature_file)
    trid_id_features = pd.read_csv(trid_id_feature_file)
    
    counter = 0

    file_names_list = file_id_features['file_name']
    file_list = []
    write_list = []
    fid_list = []
    
    for idx, file_name in enumerate(file_names_list):
        trid_name = trid_id_features.iloc[idx, 1]
        fid_name = file_id_features.iloc[idx, 1]
        
        if trid_name.find('ELF') > -1 or fid_name.find('ELF') > -1:
            print('Found: {:s} - {:s}'.format(trid_name, fid_name))
            counter += 1
            full_name = ext_drive + "VirusShare_" + file_name
            write_list =  full_name + "\n"
            file_list.append(full_name)
            fid_list.append(fid_name)


        
    fop = open('data/elf-file-list.txt','w')
    fop.writelines(write_list)
    fop.close()
    
    print("Got {:d} ELF filenames.".format(counter))

    return file_list, fid_list


def disassemble_elf_binaries(file_list, fid_list):
    # Use the command "objdump -d -M intel file_name" to dump out all 
    # the code sections of the ELF binary and generate assembly code in Intel
    # format as this is easier to read and better for machine learning 
    # feature extraction.
    # Use the command "objdump -g -x file_name -o file_name.txt to dump out
    # all header sections.
    
    counter = 0
    disassed = 0
    error_count = 0
    
    print("Disassembling {:d} binary ELF files.".format(len(file_list)))
    
    for idx, file_name in enumerate(file_list):
        file_path = file_name.rstrip() # remove the newlines or else !!!
        asm_file_name = file_path + ".elf.asm"
        hdr_file_name = file_path + ".elf.txt"
        fid_name = fid_list[idx]
        
        if (os.path.isfile(file_path)):
            fopasm = open(asm_file_name, "w")
            # Dump the assembly code listing.
            if "Intel" in fid_name:
                sub.call(["objdump", "-d", "-M intel", file_path], stdout=fopasm)
                #sub.call(["ndisasm", "-d", "-M intel", file_path], stdout=fopasm)
            elif "x86" in fid_name:
                sub.call(["objdump", "-d", "-M intel", file_path], stdout=fopasm)
            elif "ARM" in fid_name:
                sub.call(["objdump", "-d", "-marm", file_path], stdout=fopasm)
            elif "PowerPC" in fid_name:
                sub.call(["objdump", "-d", "-mpowerpc", file_path], stdout=fopasm)
            elif "Motorola" in fid_name:
                sub.call(["objdump", "-d", "-mm68k", file_path], stdout=fopasm)
            elif "SPARC" in fid_name:
                sub.call(["objdump", "-d", "-msparc", file_path], stdout=fopasm)
            elif "MIPS" in fid_name:
                sub.call(["objdump", "-d", "-mmips", file_path], stdout=fopasm)
            elif "Renesas" in fid_name: # SuperH
                sub.call(["objdump", "-d", "-msh", file_path], stdout=fopasm)
                
            # Dump the ELF section headers.
            fophdr = open(hdr_file_name, "w")
            sub.call(["readelf", "-e", file_path], stdout=fophdr)
            fophdr.close()
            
            fopasm.close()
            
            # now delete the binary, we do not need it anymore.
            # sub.call(["rm", file_path1])
            
            disassed += 1

        else:
            #print("Error: file does not exist - {:s}".format(file_path))
            error_count += 1
           
        counter += 1
        if (counter % 1000) == 0: # print progress
            print('Disassembled: {:d} - {:s}'.format(counter, file_path))    
 

    print("Disassembled {:d} ELF binaries with {:d} file path errors.".format(disassed, error_count))
    
    #sub.call(["mv", "*.asm", "/opt/vs/asm"])
    
    return


def run_processes(file_list):
    # Spawn worker processes.
    
    quart = len(file_list)/4
    train1 = tfiles[:quart]
    train2 = tfiles[quart:(2*quart)]
    train3 = tfiles[(2*quart):(3*quart)]
    train4 = tfiles[(3*quart):]

    print("Files: {:d} - {:d} - {:d}".format(len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

    trains = [train1, train2, train3, train4]
    p = Pool(4)
    p.map(disassemble_pe_binaries, trains)
    
    return


def print_help():
    print("disassemble_elf -efhiow [input_file_list.txt]")
    print("    -e /path/to/sample/binaries/")
    print("    -f /path/to/file/id/feature/file")
    
    return


# Start of Script


parser = OptionParser()
parser.add_option("-w", "--writelist", action="store_true", dest="writefilelist", default=False)
parser.add_option("-i", "--inputfile", dest="inputfilename")
parser.add_option("-o", "--outputfile", dest="outputfilename")
parser.add_option("-f", "--fileidfeature", dest="featurefilename")
parser.add_option("-p", "--packeridfeature", dest="packerfilename")
parser.add_option("-t", "--trididfeature", dest="tridfilname")
parser.add_option("-e", "--extdrive", dest="externaldrive")
#parser.add_option("-h", "--help", action="store_true", dest="printhelp", default=False)

(options, args) = parser.parse_args()

# TODO: add code for options

# Load the malware packer id features sets.
ext_drive = options.externaldrive
feature_file = options.featurefilename
in_unpacked_file_list = options.inputfilename
out_unpacked_file_list = options.outputfilename
write_file_list = options.writefilelist
#print_help = options.printhelp

# Start of Script

# TODO: everything


# TEST
ext_drive = '/opt/vs/train2/'
packer_id_file = 'data/sorted-packer-id-features-vs252.csv'
file_id_file = 'data/sorted-file-id-features-vs252.csv'
trid_id_file = 'data/sorted-trid-id-features-vs252.csv'
    
unflist, fidlist = get_elf_file_list(ext_drive, packer_id_file, file_id_file, trid_id_file)

# Do not need multi-processing for ELF binaries, there are only about 50 of them in the sample sets.
disassemble_elf_binaries(unflist, fidlist)
    
# END TEST

# End of Script

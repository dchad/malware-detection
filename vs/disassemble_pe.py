# disassemble_pe.py
#
# Performs two functions:
# 1. Generates of list of unpacked PE binary files for input to the second function.
# 2. Reads a list of unpacked PE files and uses objdump to extract PE header 
#    information from each binary then uses IDA Pro to generate the assembly code
#    file of the 32 bit binaries and objdump for the 64 bit binaries.
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
#         row format = [file_name, file_type, percentage, trid_id]
#
# Output: assembler files [input_binary_filename.pe.asm]
#         PE header files [input_binary_filename.pe.txt]
#
# or
#
# Output: unpacked_file_list.txt
#
# Author: Derek Chadwick
# Date  : 12/08/2016


from multiprocessing import Pool
from optparse import OptionParser
import subprocess as sub
import os
import sys
import pandas as pd



def write_unpacked_file_list(packer_id_feature_file, unpacked_list_file_name):
    # Load the malware packer id features sets from the sample set.
    packer_id_features = pd.read_csv(packer_id_feature_file)
    unpacked_files = packer_id_features[packer_id_features['is_packed'] == 0]
    unpacked_pe_files = unpacked_files[unpacked_files['valid_pe'] == 1]
    
    fop = open(unpacked_list_file_name, 'w')
    counter = 0
    
    for idx, file_name in enumerate(unpacked_pe_files['file_name']):
        fdesc = unpacked_pe_files.iloc[idx,1]
        if fdesc.startswith("PE32+"): # IDA Pro free does not do 64 bit PE binary files,
            continue                  # use objdump instead.
        full_name = "VirusShare_" + file_name + "\n"
        fop.write(full_name)
        counter += 1

    print("Wrote {:d} filenames.".format(counter))

    fop.close()
    
    return


def get_unpacked_file_list(packer_id_feature_file, file_id_feature_file, trid_id_feature_file):
    # Load the malware packer id features and file id features from the sample set.
    packer_id_features = pd.read_csv(packer_id_feature_file)
    file_id_features = pd.read_csv(file_id_feature_file)
    trid_id_features = pd.read_csv(trid_id_feature_file)
    
    # Get a list of unpacked PE files that are not .NET CIL format and not 64 bit.
    # IDA Pro cannot disassemble .NET files, have to use Ildisasm.exe in Visual Studio,
    # and free version will not disassemble 64 bit, use objdump instead.
    unpacked_files = packer_id_features[packer_id_features['is_packed'] == 0]
    unpacked_pe_files = unpacked_files[unpacked_files['valid_pe'] == 1]
    not_dot_net = []
    counter = 0
    dot_net_counter = 0
    amd64_bit_counter = 0
    
    # Get the trid and file rows that are for unpacked PE files.
    trids = trid_id_features[trid_id_features['file_name'].isin(unpacked_pe_files['file_name'])]
    fids = file_id_features[file_id_features['file_name'].isin(unpacked_pe_files['file_name'])]
    
    # Iterate over the unpacked PE file list and check if each is a .NET file.
    # If not a .NET or 64 bit file then add to file list.
    pe_names_list = unpacked_pe_files['file_name']
    
    for idx, file_name in enumerate(pe_names_list):
        trid_name = trids.iloc[idx, 1]
        fid_name = fids.iloc[idx, 1]
        trid_name = trid_name.lower()
        fid_name = fid_name.lower()
        
        if trid_name.find('.net') > -1 or fid_name.find('.net') > -1:
            print('Found: {:s} - {:s}'.format(trid_name, fid_name))
            dot_net_counter += 1
            continue
            
        if trid_name.find('win64') > -1 or fid_name.startswith('pe32+'):
            print('Found: {:s} - {:s}'.format(trid_name, fid_name))
            amd64_bit_counter += 1
            continue
            
        #print('Found: {:s} - {:s}'.format(trid_name, fid_name))
        not_dot_net.append(file_name)
        counter += 1
    
    file_list = []
    write_list = []
    counter = 0
    
    # Iterate over the file list and prepend the full file name.
    for file_name in not_dot_net:
        full_name = "VirusShare_" + file_name
        file_list.append(full_name)
        write_list.append(full_name + "\n")
        counter += 1

    if (len(file_list) > 0):   
        fop = open('data/temp-unpacked-pe-non-dot-net.txt','w')
        fop.writelines(write_list)
        fop.close()
    
    print("Got {:d} unpacked PE files.".format(counter))
    print("Got {:d} .NET file and {:d} 64 Bit files.".format(dot_net_counter, amd64_bit_counter))

    return file_list


def get_64bit_pe_file_list(packer_id_feature_file, file_id_feature_file, trid_id_feature_file):
    # Load the malware packer id features and file id features from the sample set.
    packer_id_features = pd.read_csv(packer_id_feature_file)
    file_id_features = pd.read_csv(file_id_feature_file)
    trid_id_features = pd.read_csv(trid_id_feature_file)
    
    # Get a list of 64 bit unpacked PE files that are not .NET CIL format.
    unpacked_files = packer_id_features[packer_id_features['is_packed'] == 0]
    unpacked_pe_files = unpacked_files[unpacked_files['valid_pe'] == 1]
    dot_net_counter = 0
    amd64_bit_counter = 0
    amd64_bit_file_list = []
    
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
            dot_net_counter += 1
            continue
            
        if trid_name.find('win64') > -1 or fid_name.startswith('pe32+'):
            print('Found: {:s} - {:s}'.format(trid_name, fid_name))
            amd64_bit_counter += 1
            amd64_bit_file_list.append(file_name)
            continue
            
        
    
    file_list = []
    write_list = []
    counter = 0
    
    # Iterate over the file list and prepend the full file name.
    for file_name in amd64bit_file_list:
        full_name = "VirusShare_" + file_name
        file_list.append(full_name)
        write_list.append(full_name + "\n")
        counter += 1

    if (len(file_list) > 0):   
        fop = open('data/temp-unpacked-64bit-pe-file-list-.txt','w')
        fop.writelines(write_list)
        fop.close()
    
    print("Got {:d} unpacked PE files.".format(counter))
    print("Got {:d} .NET file and {:d} 64 Bit files.".format(dot_net_counter, amd64_bit_counter))

    return file_list


def disassemble_pe_mem_dumps(file_list):
    # Disassemble the unpacked memory segments dumped by the unpack tool.
    # 
    # TODO: everything    
    
    return


def disassemble_pe_binaries(file_list):
    # Can use the command "objdump -d file_name -o file_name.asm" to dump out all 
    # sections of the PE binary and generate assembly code.
    # However the objdump output is not optimal for machine learning objectives, 
    # as we need to translate call operand target addresses to function names, 
    # A better alternative is to use IDA Pro in batch mode to generate the
    # assembly code.
    #
    # NOTE: IDA Pro Demo does not save any output, IDA Pro Free has a
    #       popup window on startup that prevents batch processing mode.
    #
    
    counter = 0
    disassed = 0
    error_count = 0
    pid = os.getpid()
    log_file = "data/" + str(pid) + '-pe-disass-log.txt'
    
    smsg = "{:d} Disassembling {:d} binary PE32 files.".format(pid, len(file_list))
    print(smsg)
    flog = open(log_file, 'w')
    flog.write(smsg + "\n")
    
    for file_name in file_list:
        file_path = file_name.rstrip() # remove the newlines or else !!!
        asm_file_name = file_path + ".pe.asm"
        hdr_file_name = file_path + ".pe.txt"
            
        if (os.path.isfile(file_path)):
            
            #command_line = "objdump -d {:s} > {:s}".format(file_path1, asm_file_name)
            #sub.call(["rasm2", "-d", "-a", "x86", "-s", "intel", "-f", file_path, "-O", asm_file_name])
            #sub.call(["./idaq69", "-B", file_path])
            #sub.call(["python", "vivisect", "-B", file_path])
            #sub.call(["objdump", "-g", "-x", "-D", "-s", "-t", "-T", "-M", "intel", file_path], stdout=fop)
            #sub.call(["ndisasm", "-a", "-p", "intel", file_path])
            
            # Dump the assembly code listing.
            sub.call(["wine", '/opt/vs/ida/idag.exe', "-B", "-P+", file_path])
            
            # now delete the binary, we do not need it anymore.
            # sub.call(["rm", file_path])
            
            disassed += 1

        else:
            error_count += 1
           
        counter += 1
        
        if (counter % 10) == 0: # print progress
            smsg = '{:d} Disassembled: {:d} - {:s}'.format(pid, counter, file_name)
            print(smsg)
            flog.write(smsg + "\n")    
 

    smsg = "{:d} Disassembled {:d} binaries with {:d} file path errors.".format(pid, disassed, error_count)
    print(smsg)
    flog.write(smsg + "\n")
    flog.close()
    
    #sub.call(["mv", "*.asm", "/opt/vs/asm"])
    
    return


def disassemble_pe64_binaries(file_list):
    counter = 0
    disassed = 0
    error_count = 0
    pid = os.getpid()
    log_file = "data/" + str(pid) + '-pe-disass-log-64.txt'
    
    smsg = "{:d} Disassembling {:d} binary PE64 files.".format(pid, len(file_list))
    print(smsg)
    flog = open(log_file, 'w')
    flog.write(smsg + "\n")
    
    for file_name in file_list:
        file_path = file_name.rstrip() # remove the newlines or else !!!
        asm_file_name = file_path + ".64.pe.asm"
        #hdr_file_name = file_path + ".64.pe.txt"
            
        if (os.path.isfile(file_path)):
            fop = open(asm_file_name, 'w')
            # Dump the assembly code listing.
            sub.call(["objdump", "-g", "-x", "-D", "-s", "-t", "-T", "-M", "intel", file_path], stdout=fop)
            disassed += 1
            fop.close
        else:
            error_count += 1
           
        counter += 1
        
        if (counter % 10) == 0: # print progress
            smsg = '{:d} Disassembled: {:d} - {:s}'.format(pid, counter, file_name)
            print(smsg)
            flog.write(smsg + "\n")    
 

    smsg = "{:d} Disassembled {:d} PE64 binaries with {:d} file path errors.".format(pid, disassed, error_count)
    print(smsg)
    flog.write(smsg + "\n")
    flog.close()
    
    return


def extract_pe_headers(file_list):
    # Use the command "objdump -g -x file_name" to dump out all 
    # the header sections of the PE binary. 
    # Separating this from the disassembly because of errors with
    # IDA Pro disassembly making everything too complicated.
    
    counter = 0
    disassed = 0
    error_count = 0
    
    print("Extracting headers from {:d} binary PE files.".format(len(file_list)))
    
    for file_name in file_list:
        file_path = file_name.rstrip() # remove the newlines or else !!!
        #asm_file_name = file_path + ".pe.asm"
        hdr_file_name = file_path + ".pe.txt"
            
        if (os.path.isfile(file_path)):
            
            # Dump the PE section headers and import tables.
            fop = open(hdr_file_name, "w")
            sub.call(["objdump", "-g", "-x", file_path], stdout=fop)
            fop.close()
            
            disassed += 1

        else:
            #print("Error: file does not exist - {:s}".format(file_path))
            error_count += 1
           
        counter += 1
        if (counter % 1000) == 0: # print progress
            print('Extracted: {:d} - {:s}'.format(counter, file_name))    
 

    print("Extracted {:d} binaries with {:d} file path errors.".format(disassed, error_count))
    
    return


def rename_asm_files(ext_dir, new_dir, file_extension):
    # Rename all the PE ASM files and move them to a new directory
    # so it is easier to process them.
    # Example file name extensions: 
    # filename.pe.asm - 32 bit 
    # filename.64.pe.asm - 64 bit
    # filename.net.pe.asm - .NET CIL
    
    file_list = os.listdir(ext_dir)
    counter = 0
    
    for fname in file_list:
        if fname.endswith('.asm'):
            file_path = ext_dir + fname
            trunc_name = fname[0:fname.find('.asm')]
            new_path = new_dir + trunc_name + file_extension
            result = sub.check_call(['mv', file_path, new_path])
            counter += 1

            if (counter % 1000) == 0:
                print('Renamed {:d} ASM files.'.format(counter))

    print('Completed rename of {:d} ASM files.'.format(counter))
    
    return


def validate_disassembly(asm_path, hdr_path, file_ext): 
    # Check disassembly results for the PE/COFF files in the malware set.

    t1asm = os.listdir(asm_path)
    t1hdr = os.listdir(hdr_path)
    asm_files = []
    hdr_files = []

    for fname in t1asm:
        if fname.endswith('.pe.asm'):
            asm_files.append(fname)

    for fname in t1hdr:
        if fname.endswith('.pe.txt'):
            hdr_files.append(fname)

    print("asm dir: {:d} asm files {:d} hdr dir {:d} hdr files {:d}".format(len(t1asm),len(asm_files),len(t1hdr),len(hdr_files)))
    
    counter = 0
    missing_hdr_list = []

    for fname in asm_files:
        hdr_name = fname.replace('.asm', '.txt')
        if hdr_name not in hdr_files:
            print("{:s} not in header file list.".format(hdr_name))
            counter += 1
            missing_hdr_list.append(hdr_name)

    print("{:d} missing header files.".format(counter))
 
    counter = 0
    missing_asm_list = []

    for fname in hdr_files:
        asm_name = fname.replace('.txt','.asm')
        if asm_name not in asm_files:
            print("{:s} not in asm file list.".format(asm_name))
            counter += 1
            missing_asm_list.append(asm_name)

    print("{:d} missing assembly files.".format(counter))

    if len(missing_asm_list) > 0:
        counter = 0
        fop = open('data/temp-disass-missing-asm-files' + file_ext + '.txt', 'w')
        for fname in missing_asm_list:
            fop.write(fname + "\n")
            counter += 1

        fop.close()
        print("Wrote {:d} missing asm file names.".format(counter))

    if len(missing_hdr_list) > 0:
        counter = 0
        fop = open('data/temp-disass-missing-hdr-files' + file_ext + '.txt', 'w')
        for fname in missing_hdr_list:
            fop.write(fname + "\n")
            counter += 1

        fop.close()
        print("Wrote {:d} missing hdr file names.".format(counter))
        
    counter = 0
    bad_asm_list = []

    for fname in asm_files:
        fsize = os.path.getsize(asm_path + fname)
        if fsize < 1000:
            print("{:s} bad output, filesize = {:d}.".format(fname, fsize))
            counter += 1
            bad_asm_list.append(fname)

    print("{:d} bad asm files.".format(counter))

    counter = 0
    bad_hdr_list = []

    for fname in hdr_files:
        fsize = os.path.getsize(hdr_path + fname)
        if fsize < 1000:
            print("{:s} bad output, filesize = {:d}.".format(fname, fsize))
            counter += 1
            bad_hdr_list.append(fname)

    print("{:d} bad header files.".format(counter))

    if len(bad_hdr_list) > 0:
        counter = 0
        fop = open('data/temp-disass-bad-hdr-files' + file_ext + '.txt', 'w')
        for fname in bad_hdr_list:
            fop.write(fname + "\n")
            counter += 1

        fop.close()
        
    print("Wrote {:d} bad hdr file names.".format(counter))

    if len(bad_asm_list) > 0:
        counter = 0
        fop = open('data/temp-disass-bad-asm-files' + file_ext + '.txt', 'w')
        for fname in bad_asm_list:
            fop.write(fname + "\n")
            counter += 1

        fop.close()
        
    print("Wrote {:d} bad asm file names.".format(counter))
    
    
    return


def run_disassembly_processes(tfiles):
    # Spawn worker processes.
    
    quart = len(tfiles)/4
    train1 = tfiles[:quart]
    train2 = tfiles[quart:(2*quart)]
    train3 = tfiles[(2*quart):(3*quart)]
    train4 = tfiles[(3*quart):]

    print("Files: {:d} - {:d} - {:d}".format(len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

    trains = [train1, train2, train3, train4]
    p = Pool(4)
    p.map(disassemble_pe_binaries, trains)
    
    return


def run_header_extraction_processes(tfiles):
    # Spawn worker processes.
    
    quart = len(tfiles)/4
    train1 = tfiles[:quart]
    train2 = tfiles[quart:(2*quart)]
    train3 = tfiles[(2*quart):(3*quart)]
    train4 = tfiles[(3*quart):]

    print("Files: {:d} - {:d} - {:d}".format(len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

    trains = [train1, train2, train3, train4]
    p = Pool(4)
    p.map(extract_pe_headers, trains)
    
    return


def print_help():
    print("disassemble_pe -efhiow [input_file_list.txt]")
    print("    -e /path/to/sample/binaries/")
    print("    -f /path/to/file/id/feature/file")
    
    return


class Multi_Params(object):
    def __init__(self, outfile="", tokenfile="", fieldnames=[], filelist=[]):
        self.out_file = outfile
        self.token_file = tokenfile
        self.field_names = fieldnames
        self.file_list = filelist
        
        
# Start of Script
if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-w", "--writelist", action="store_true", dest="writefilelist", default=False)
    parser.add_option("-i", "--inputfile", dest="inputfilename")
    parser.add_option("-o", "--outputfile", dest="outputfilename")
    parser.add_option("-f", "--fileidfeature", dest="featurefilename")
    parser.add_option("-p", "--packeridfeature", dest="packerfilename")
    parser.add_option("-t", "--trididfeature", dest="tridfilname")
    parser.add_option("-e", "--extdrive", dest="externaldrive")
    parser.add_option("-s", "--sixtyfour", dest="sixtyfour")
    parser.add_option("-m", "--memdumps", dest="memorydumps")
    #parser.add_option("-h", "--help", action="store_true", dest="printhelp", default=False)

    (options, args) = parser.parse_args()

    # TODO: add code for options

    # Load the malware packer id features sets.
    ext_drive = options.externaldrive
    feature_file = options.featurefilename
    in_unpacked_file_list = options.inputfilename
    out_unpacked_file_list = options.outputfilename
    write_file_list = options.writefilelist
    disass_64bit = options.sixtyfour
    disass_memdumps = options.memorydumps

    #print_help = options.printhelp

    #if print_help == True:
    #    print_help()
    #    sys.exit(0)
        

    if write_file_list == True:
        # Generate a list of upacked PE binaries.
        write_unpacked_file_list(feature_file, out_unpacked_file_list)


    if ext_drive != None:
        #ext_drive = '/opt/vs/train1/'
        #ext_drive = '/opt/vs/train2/'
        #ext_drive = '/opt/vs/train3/'
        #ext_drive = '/opt/vs/train4/'
        #ext_drive = '/opt/vs/apt/'

        # Read the list of unpacked PE files and disassemble.
        if in_unpacked_file_list != None:
            
            fip = open(in_unpacked_file_list)
            file_list = fip.readlines()
            fip.close()
            
            for idx, fname in enumerate(file_list):
                file_list[idx] = ext_drive + fname
            
            run_disassembly_processes(file_list)
            
        else:

            # Just get a list of files from the input directory and disassemble.
            tfiles = os.listdir(ext_drive)
            
            for idx, fname in enumerate(tfiles):
                tfiles[idx] = ext_drive + fname

            run_disassembly_processes(tfiles)

    elif disass_64bit != None:
        # Use objdump for amd64 PE binaries, do not bother with multiprocessing.
        
        packer_id_file = 'data/sorted-packer-id-features-vs251.csv'
        file_id_file = 'data/sorted-file-id-features-vs251.csv'
        trid_id_file = 'data/sorted-trid-id-features-vs251.csv'
        ext_drive = '/opt/vs/train1/'
        file_list = get_64bit_pe_file_list()
        
        disassemble_64bit_binaries(file_list)
    
    elif disass_memdumps != None:
        # Use objdump for 64bit and IDA Pro for 32bit to disassemble memory dumps.
        # TODO: everything!
        fip = open('data/pe-mem-dump-list.txt', 'r')
        in_lines = fip.readlines()
        file_list = []
        for line in in_lines:
            file_list.append(line.rstrip())
            
        disassemble_pe_mem_dumps(file_list)
        
    else:
        
        # If no command line options.
        #packer_id_file = 'data/sorted-packer-id-features-apt.csv'
        #file_id_file = 'data/sorted-file-id-features-apt.csv'
        #trid_id_file = 'data/sorted-trid-id-features-apt.csv'
        #ext_drive = '/opt/vs/apt/'
        
        packer_id_file = 'data/sorted-packer-id-features-vs264.csv'
        file_id_file = 'data/sorted-file-id-features-vs264.csv'
        trid_id_file = 'data/sorted-trid-id-features-vs264.csv'
        ext_drive = '/opt/vs/train4/'
        
        unflist = get_unpacked_file_list(packer_id_file, file_id_file, trid_id_file)
        
        #disassemble_pe_binaries(unflist)
        
        # TEMP FIX
        file_list = os.listdir('/opt/vs/train4asm/')
        completed_list = []
        process_list = []
        
        print("Got {:d} total files.".format(len(file_list)))
        
        for idx, fname in enumerate(file_list):
            if fname.endswith(".asm"):
                completed_list.append(fname[0:fname.find(".asm")])
        
        print("Got {:d} completed ASM files.".format(len(completed_list)))
        
        for idx, fname in enumerate(unflist):
            if fname not in completed_list:
                process_list.append(ext_drive + fname)
          
        run_disassembly_processes(process_list)
        # END TEMP FIX
    
        # print("Processing {:d} files out of {:d} total unpacked PE files.".format(len(file_list), len(unflist)))
        
        # run_header_extraction_processes(file_list)
        
        # run_disassembly_processes(unflist)
        
        
        #rename_asm_files('/opt/vs/train4/', '/opt/vs/train4asm/', '.pe.asm')
        
        #validate_disassembly('/opt/vs/aptasm/', '/opt/vs/apthdr/')
    
# End of Script


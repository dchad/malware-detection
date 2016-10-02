# feature_extraction_file_id.py
#
# Generate file magic signature and TrID signature IDs for all malware samples.
#
# Inputs: av-file-id-labels.csv (scalar labels for all file types.)
#         row format = [file_type, id]
#
#         av-trid-id-labels.csv (scalar labels for all TrID types.)
#         row format = [file_type, id]
#
# Output: xxxx-sorted-file-id-features.csv ( 4 x feature files )
#         row format = [file_name, file_type, file_id]
#
#         xxx-sorted-trid-id-features.csv (4 x feature files)
#         row format = [file_name, file_type, percentage, trid_id]
#
#         Combined into sorted feature files:
#
#         sorted-file-id-features.csv
#         sorted-trid-id-features.csv
#
#
# Author: Derek Chadwick
# Date  : 27/08/2016



from multiprocessing import Pool
import os
import sys
import re
import pandas as pd
import subprocess as sub




def load_file_id_map():
    # Load the file ID scalar labels and create a map. 
    file_id_map = {}

    counter = 0
    fip = open('data/av-file-id-labels.csv','r')
    in_lines = fip.readlines()
    fip.close()
    
    for idx in range(1,len(in_lines)): # Skip the column header row.
        tokens = in_lines[idx].split(',')
        file_type_name = tokens[0]
        if file_type_name not in file_id_map.keys():
            file_id_map[file_type_name] = int(tokens[1])
            counter += 1

    
    print('Completed loading {:d} file IDs.'.format(counter))
    
    return file_id_map


# DEPRECATED: will get inconsistent labelling during multiprocessing, use in singlepocessing only.
def save_file_id_map(file_id_map):
    # Write the file scalar label map to csv file.
    counter = 0
    pid = os.getpid()
    file_name = "data/" + str(pid) + "-av-file-id-labels.csv.csv"
    fop = open(file_name,'w')
    fop.write("file_type,id\n")
    
    for file_type in file_id_map.keys():
        fop.write(file_type + "," + str(file_id_map[file_type]) + "\n")
        counter += 1

    
    fop.close()
    
    print('Completed writing {:d} file IDs.'.format(counter))
    
    return    

                      
def load_trid_id_map():
    # Load the TrID ID scalar labels and create a map.
    trid_id_map = {}

    counter = 0
    fip = open('data/av-trid-id-labels.csv','r')
    in_lines = fip.readlines()
    fip.close()
    
    for idx in range(1,len(in_lines)): # Skip the column header row.
        tokens = in_lines[idx].split(',')
        file_type_name = tokens[0]
        if file_type_name not in trid_id_map.keys():
            trid_id_map[file_type_name] = int(tokens[1])
            counter += 1

    
    print('Completed loading {:d} trid IDs.'.format(counter))
    
    return trid_id_map


# DEPRECATED: will get inconsistent labelling during multiprocessing, use in singlepocessing only.
def save_trid_id_map(trid_id_map):
    # Write the TrID label map to csv file.
    counter = 0
    pid = os.getpid()
    file_name = "data/" + str(pid) + "-av-trid-id-labels.csv.csv"
    fop = open(file_name,'w')
    fop.write("file_type,id\n")
    
    for file_type in trid_id_map.keys():
        fop.write(file_type + "," + str(trid_id_map[file_type]) + "\n")
        counter += 1

    
    fop.close()
    
    print('Completed writing {:d} trid IDs.'.format(counter))
    
    return 
                      
    

def sort_and_save_file_id_feature_file():
    # Load in the combined feature files, sort and save.
    # NOTE: add a file name argument so the final filename can be
    #       specified during runs on multiple datasets.
    
    fid = pd.read_csv('data/file-id-features.csv')
    # DataFrame.sort() is deprecated, but this is an old version of pandas, does not have sort_values().
    sorted_ids = fid.sort('file_name')
    sorted_ids.to_csv('data/sorted-file-id-features.csv', index=False)
    sorted_ids.head(20)
    
    return


def combine_file_id_files():
    # Function to combine the four file id feature files in one file
    # 1. list data directory
    # 2. For each file in file list that matches (\d\d\d\d-file-id-features.csv)
    # 3. Trim the filenames if necessary (should remove VirusShare_  prefix).
    # 4. Concatenate the unsorted file id feature files.
    # 5. Sort and write to data/sorted-file-id-features.csv
    # NOTE: add a file name argument so the final filename can be
    #       specified during runs on multiple datasets.
    
    fop = open('data/file-id-features.csv','w')
    fop.write('file_name,file_type,file_id\n')
    p1 = re.compile('\d{3,5}-sorted-file-id-features.csv') # This is the PID prefix for each file.
    file_list = os.listdir('data/')
    counter = 0
    
    for file_name in file_list:
        if p1.match(file_name):
            fip = open('data/' + file_name, 'r')
            in_lines = fip.readlines()
            fop.writelines(in_lines)
            counter += len(in_lines)
            fip.close()
            
    print('Completed combine of {:d} file ID features.'.format(counter))  
    
    fop.close()
    
    sort_and_save_file_id_feature_file()
    
    return

    
def sort_and_save_trid_id_feature_file():
    fid = pd.read_csv('data/trid-id-features.csv')
    # DataFrame.sort() is deprecated, but this is an old version of pandas, does not have sort_values().
    sorted_ids = fid.sort('file_name')
    sorted_ids.to_csv('data/sorted-trid-id-features.csv', index=False)
    sorted_ids.head(20)
    
    return
    
    
def combine_trid_id_files():
    fop = open('data/trid-id-features.csv','w')
    fop.write('file_name,file_type,percentage,trid_id\n')
    p1 = re.compile('\d{3,5}-sorted-trid-id-features.csv') # This is the PID prefix for each file.
    file_list = os.listdir('data/')
    counter = 0
    
    for file_name in file_list:
        if p1.match(file_name):
            fip = open('data/' + file_name, 'r')
            in_lines = fip.readlines()
            fop.writelines(in_lines)
            counter += len(in_lines)
            fip.close()
            
    print('Completed combine of {:d} trid ID features.'.format(counter))  
    
    fop.close()
    
    sort_and_save_trid_id_feature_file()
    
    return


def generate_sample_file_id(file_list):
    # Generate scalar file ID for each sample.
    pid = os.getpid()
    file_name = "data/" + str(pid) + "-sorted-file-id-features.csv"
    fop = open(file_name,'w')
    out_lines = []
    file_id_map = load_file_id_map()
    signat = 'unknown'
    file_counter = 0
    id_counter = len(file_id_map.keys())
    file_id_map_changed = False
    
    for idx, file_name in enumerate(file_list):
        tokens = file_name.split('_')
        truncated_file_name = tokens[1] # remove the VirusShare_ prefix from the filename.
        file_path = ext_drive + file_name
        file_id = 0
        
        signat = sub.check_output(["file","-b", file_path]) # Use the brief option, we do not need the file name.
        signat = signat.replace(',','').rstrip() # get rid of newlines and commas they are annoying
        
        
        if signat in file_id_map.keys():
            # print("Signature: {:s}".format(signat))
            file_id = file_id_map[signat]
        else:
            id_counter += 1
            file_id_map[signat] = id_counter
            file_id = id_counter
            file_id_map_changed = True
  
            
        row = truncated_file_name + "," + signat + "," + str(file_id) + "\n"
    
        out_lines.append(row)
        
        file_counter += 1
        
        if (idx % 1000) == 0: # print progress
            fop.writelines(out_lines)
            out_lines = []
            print('{:s} - {:s} - {:d} - {:s}'.format(str(pid), truncated_file_name, idx, signat))


    if len(out_lines) > 0:
        fop.writelines(out_lines)
        out_lines = []

    fop.close()

    print('{:s} - Completed {:d} files.'.format(str(pid), file_counter))
    
#    if file_id_map_changed:
#        save_file_id_map(file_id_map)
    
    return


def generate_sample_trid_id(file_list):
    # Generate scalar file ID for each sample.
    pid = os.getpid()
    file_name = "data/" + str(pid) + "-sorted-trid-id-features.csv"
    fop = open(file_name,'w')
    out_lines = []
    trid_id_map = load_trid_id_map()

    file_counter = 0
    id_counter = len(trid_id_map.keys())
    trid_id_map_changed = False
    high_score_line = "unknown"
    
    p1 = re.compile('.*(\d+\.\d+)\% (.+) \(\d+\/\d+\/\d+\)') # Extract the items of interest.
    
    for idx, file_name in enumerate(file_list):
        tokens = file_name.split('_')
        truncated_file_name = tokens[1] # remove the VirusShare_ prefix from the filename.
        file_path = ext_drive + file_name
        file_id = 0
        high_score_line = "unknown"
        
        signat = sub.check_output(["/opt/vs/trid", file_path])
        components = signat.split('\n')
        for idx2, line in enumerate(components):
            if line.startswith("Collect"):
                high_score_line = components[idx2 + 1] # If we find a TrID signature the next line
                break                                  # contains the highest probability file type.
                
                
        m = p1.match(high_score_line)
        if m != None:
            percent = m.group(1)
            file_type = m.group(2).replace(',','')
        else:
            percent = "0.0"
            file_type = "unknown"
            
            
        if file_type in trid_id_map.keys():
            file_id = trid_id_map[file_type]
        else:
            id_counter += 1
            trid_id_map[file_type] = id_counter
            file_id = id_counter
            trid_id_map_changed = True
            
        row = truncated_file_name + ',' + file_type + ',' + percent + ',' + str(file_id) + '\n'
    
        out_lines.append(row)
        
        file_counter += 1
        
        if (idx % 1000) == 0: # print progress
            fop.writelines(out_lines)
            out_lines = []
            print('{:s} - {:s} - {:d} - {:s}'.format(str(pid), truncated_file_name, idx, file_type))


    if len(out_lines) > 0:
        fop.writelines(out_lines)
        out_lines = []

    fop.close()

    print('{:s} - Completed {:d} files.'.format(str(pid), file_counter))
    
#    if trid_id_map_changed:
#        save_trid_id_map(trid_id_map)
       
    return

    
# Start of script.

# TODO: add command line arguments to specify input/output files.

#ext_drive = '/opt/vs/train1/'
#ext_drive = '/opt/vs/train2/'
#ext_drive = '/opt/vs/train3/'
#ext_drive = '/opt/vs/train4/'
ext_drive = '/opt/vs/apt/'
#ext_drive = '/opt/vs/train/'

tfiles = os.listdir(ext_drive)

# TEST

#generate_sample_file_id(tfiles)
#combine_file_id_files()
#print('Completed processing {:d} files.'.format(len(tfiles)))

#generate_sample_trid_id(tfiles)
#print('Completed processing {:d} files.'.format(len(tfiles)))
#combine_trid_id_files()

# END TEST


quart = len(tfiles)/4
train1 = tfiles[:quart]
train2 = tfiles[quart:(2*quart)]
train3 = tfiles[(2*quart):(3*quart)]
train4 = tfiles[(3*quart):]

print("Files: {:d} - {:d} - {:d}".format(len(tfiles), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

# First generate file id magic signature feature set.

trains = [train1, train2, train3, train4]
p = Pool(4)
p.map(generate_sample_file_id, trains)

print('Completed processing {:d} files.'.format(len(tfiles)))

combine_file_id_files()

# Now generate the TrID signatrue features.

p.map(generate_sample_trid_id, trains)

print('Completed processing {:d} files.'.format(len(tfiles)))

combine_trid_id_files()

# End of Script.

# generate_function_counts.py
#
# Read a bunch of call graph files in GraphViz format and generate function count
# feature sets in CSV format.
#
# Input : Call graph files in GraphViz format.
#         GraphViz directed graph format:
#
#            digraph graph_name {
#                node_name1 -> { node_name2 ; node_name3 ; .... }
#                .
#                .
#                .
#                node_nameX -> { node_nameY ; node_nameZ ; .... }
#            }
# 
#
# Output: all-reduced-function-counts.csv
#         row format = [file_name, [list of function names]...]
#
#         all-reduced-function-column-names-singleline.txt
#         all-reduced-function-column-names-multiline.txt
#         (lists of function names extracted from the call graphs to be used as column names for the feature sets)
#
# Author: Derek Chadwick
# Date  : 14/11/2016
#
# TODO: optimise and many many things

import numpy as np
import pandas as pd
import graph as gra # http://www.python-course.eu/graphs_python.php
import os
from csv import writer
from multiprocessing import Pool
import re



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



def generate_function_counts(call_graph_file_list, column_names_file, feature_file_name):
    # Generate function counts from graph files of the ASM malware samples.
    
    counter = 0
    error_count = 0
    graph_name = 'none'
    graph_counter = 0
    
    all_column_names = reduce_column_names(column_names_file)
    col_names_len = len(all_column_names)
    feature_column_names = all_column_names[1:] # Skip the "filename" column.
    
    pid = os.getpid()
    print('Process id: {:d}'.format(pid))  
    print('Call graph function counts file: {:s}'.format(feature_file_name))
    feature_file = open(feature_file_name, 'w')
    fw = writer(feature_file)
    fw.writerow(all_column_names)
    
    call_graph_function_features = []
    function_counts = [0] * (col_names_len - 1) # NOTE: do not include the sample name in the function counts.
    
    for call_graph_file in call_graph_file_list:
        print("Processing call graph file: {:s}".format(call_graph_file))

        with open(call_graph_file, 'r') as cfg:
            for line in cfg:
                
                if line.startswith(' }'): # End of current graph, append the function counts to the feature list.
                    call_graph_function_features.append([graph_name] + function_counts)
                    continue
                    
                if line.startswith('digraph'):
                    function_counts = [0] * (col_names_len - 1) # NOTE: do not include the sample name in the function counts.
                    tokens = line.split(' ')
                    graph_name = tokens[1]
                    graph_counter += 1
                    continue
                    
                line.rstrip()  # get rid of newlines they are annoying.
                # get rid of all these things they are annoying.
                line = line.replace(';',' ').replace('{',' ').replace('}',' ').replace('->',' ').replace('\'',' ').replace('\"',' ')
                parts = line.split() # tokenize graph line
                
                function_dict = {}
                
                # now generate the function counts for this call graph
                
                for func in parts:
                    # lets try to reduce the vast number of functions.
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

                    if (func in function_dict):
                        function_dict[func] += 1
                    else:
                        function_dict[func] = 1
                
                # now generate the output row for this call graph

                
                for func in function_dict:
                    for idx, cname in enumerate(feature_column_names): # NOTE: Do not include the "filename" column.
                        if func == cname:
                            function_counts[idx] = function_dict[func]
                            break
                    
                
                
                # Print progress and write out rows
                counter += 1
                if ((counter + 1) % 10000) == 0:
                    print("{:d} GraphViz File: {:s} Graph: {:s} Graph Count: {:d} Line Count: {:d}".format(pid, call_graph_file, graph_name, graph_counter, counter))
                    fw.writerows(call_graph_function_features)
                    call_graph_function_features = []
                    
            # Write remaining files
            if len(call_graph_function_features) > 0:
                fw.writerows(call_graph_function_features)
                call_graph_function_features = []  
    

    # We are done.

    feature_file.close()
    
    validate_feature_set(feature_file_name, col_names_len)
    
    print("Completed processing {:d} graph lines.".format(counter))
    
    return


def validate_feature_set(feature_set_file_name, feature_set_len):
    fip = open(feature_set_file_name, 'r')
    fop = open("data/temp-pe-function-count-errors.txt", 'w')
    feature_count = 0
    error_count = 0

    for line in fip:
        line = line.rstrip()
        tokens = line.split(',')
        sample_name = tokens[0]
        feature_count = len(tokens)

        if feature_count != feature_set_len:
            print("ERROR: Feature counts inconsistent: {:d} {:d}".format(feature_count, feature_set_len))
            error_count += 1
            fop.write(str(feature_count) + " : " + line[:128] + '\n')

        if sample_name.endswith('.elf'):
            print("ERROR: ELF sample in PE feature set: {:s}".format(sample_name))
            error_count += 1
            fop.write(str(feature_count) + " : " + line[:128] + '\n')


    fip.close()
    fop.close()

    print("Feature set validation: {:d} errors.".format(error_count))

    return


# Start of script.
if __name__ == "__main__":

    #TODO: parse command line options for input/output file names.

    ext_drive = '/opt/vs/'
    sample_set_id = 'vs263'
    #sample_set_id = 'apt'

    feature_file_name = 'data/call-graph-reduced-function_counts-' + sample_set_id + '.csv'
    # DEPRECATED: column_name_file = 'data/all-column-names-single-line-' + sample_set_id + '.txt'
    column_name_file = 'data/all-column-names-multi-line-' + sample_set_id + '.txt'

    pecallgraphs = re.compile('\d{3,5}-pe-call-graphs-' + sample_set_id +'.gv') 

    file_list = os.listdir(ext_drive)
    call_graph_files = []

    counter = 0
    for file_name in file_list:
        if pecallgraphs.match(file_name):
            call_graph_files.append('/opt/vs/' + file_name)
            counter += 1
            print("Found call graph file: {:s}".format(file_name))



    generate_function_counts(call_graph_files, column_name_file, feature_file_name)


    print("Completed function counts for sample set id: {:s}".format(sample_set_id))

# End of Script









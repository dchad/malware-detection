# generate_function_column_names.py
#
# Read a bunch of call graph files in GraphViz format and generate column names for function count
# feature sets in txt format.
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
# Output: 
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

# Determine if a string is all ascii characters.

def is_ascii(s):
    return all(ord(c) < 128 for c in s)


def is_printable_ascii(s):
    return all(ord(c) > 31 and ord(c) < 127 for c in s)


def generate_column_names(call_graph_file, column_file):
    counter = 0
    column_names = ['filename']
    graph_names = []
    graph_name = "none"
    graph_functions = {}

    #fapi = open("data/APIs.txt")
    #defined_apis = fapi.readlines()
    #defined_apis = defined_apis[0].split(',')
    #fapi.close()
    
    pid = os.getpid()
    print('Process id: {:d}'.format(pid))
    #column_names_file = 'data/' + str(pid) + '-' + column_file 
    print('Column names file: {:s}'.format(column_file))
    #graph_names_file = 'data/' + str(pid) + '-graph-names.csv'  
    #print('Graph names file: {:s}'.format(graph_names_file))    

    with open(call_graph_file, 'r') as cfg:
        print("Starting graph file: {:s}".format(call_graph_file))
        for line in cfg:
            
            if line.startswith('digraph'):
                tokens = line.split()
                graph_name = tokens[1]
                graph_names.append(graph_name)
                continue
                
            line = line.rstrip('\r\n')  # get rid of newlines they are annoying.
            # get rid of all these things they are annoying.
            line = line.replace(';',' ').replace('{',' ').replace('}',' ').replace('->',' ').replace('\'',' ').replace('\"',' ')
            parts = line.split() # tokenize call graph line
            
            
            #graph_name = parts[0] # this is for single line call graphs.
            #parts = parts[1:]
            #graph_names.append(graph_name)
            #graph_functions = {}
            
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
                    
                if func not in column_names:    
                    column_names.append(func)

 
            counter += 1
            # Print progress
            if ((counter + 1) % 10000) == 0:
                print("Call Graph File: {:s} Processed line number {:d} Graph name {:s} Total column names {:d}".format(call_graph_file, counter, graph_name, len(column_names)))       

                
    with open(column_file, 'w') as fop:
        fw = writer(fop)
        fw.writerow(column_names)
    
    print("Completed writing {:d} column names.".format(len(column_names)))

    #with open(graph_names_file, 'w') as gras:
    #    fw = writer(gras)
    #    fw.writerow(graph_names)
    
    #print("Completed writing {:d} graph names.".format(len(graph_names)))
    
    return



def merge_column_names_single_line(column_name_files, combined_column_name_file):
    # Generate the merged column names file single line.
    counter = 0
    column_names = []
    
    for cnamefile in column_name_files:
        with open(cnamefile, 'r') as cras:
            print("Singleline Starting file: {:s}".format(cnamefile))
            colstr = cras.readline()
            colnames = colstr.split(',')
            for cname in colnames:
                if cname not in column_names:
                    column_names.append(cname)

                counter += 1
                # Print progress
                if ((counter + 1) % 1000) == 0:
                    print("{:s} Processed column names {:d}".format(cnamefile, counter))       

    with open(combined_column_name_file, 'w') as cols:
        fw = writer(cols)
        fw.writerow(column_names)

    print("Singleline - completed writing column names total = {:d}".format(len(column_names)))
    
    return


def merge_column_names_multi_line(column_name_files, combined_column_name_file):
    #Generate the merged column names file multiline.
    counter = 0
    column_names = []
    
    for cnamefile in column_name_files:
        with open(cnamefile, 'r') as cras:
            print("Multiline Starting file: {:s}".format(cnamefile))
            colstr = cras.readline()
            colnames = colstr.split(',')
            for cname in colnames:
                if cname not in column_names:    
                    column_names.append(cname)

                counter += 1
                # Print progress
                if ((counter + 1) % 1000) == 0:
                    print("{:s} Processed column names {:d}".format(cnamefile, counter))       

    with open(combined_column_name_file, 'w') as cols:
        for cname in column_names:
            outline = cname + "\n"
            cols.write(outline)

    print("Multiline - completed writing column names total = {:d}".format(len(column_names)))
    
    return



# Start of script.
if __name__ == "__main__":

    #TODO: parse command line options for input/output file names/sample set id etc...

    ext_drive = '/opt/vs/'
    sample_set_id = 'vs254'

    pecallgraphs = re.compile('\d{3,5}-pe-call-graphs-' + sample_set_id +'.gv') # This is the PID prefix for each file.

    file_list = os.listdir(ext_drive)
    call_graph_files = []
    column_name_files = []

    counter = 0
    for file_name in file_list:
        if pecallgraphs.match(file_name):
            call_graph_files.append(file_name)
            counter += 1
            column_name_file = 'data/reduced-column-names-' + sample_set_id + '-' + str(counter) + '.txt'
            column_name_files.append(column_name_file)
            print("Found call graph file: {:s}".format(file_name))
            print("Column name file: {:s}".format(column_name_file))


    for idx, call_graph_file_name in enumerate(call_graph_files):
        print("Doing column names: {:s} - {:s}".format(call_graph_file_name, column_name_files[idx]))
        generate_column_names('/opt/vs/' + call_graph_file_name, column_name_files[idx])


    # We are going to generate single line and multi line files for convenience.
    merge_column_names_single_line(column_name_files, 'data/all-column-names-single-line-' + sample_set_id + '.txt')
    merge_column_names_multi_line(column_name_files, 'data/all-column-names-multi-line-' + sample_set_id + '.txt')


# End of Script


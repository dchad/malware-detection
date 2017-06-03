# feature_reduction_function_names.py
#
# Read a a bunch of function name feature sets and use chi2 tests
# to remove features that are independent of the label.
#
# Input : function count feature sets in CSV files.
#         row format = [file_name, [list of function names]...]
#
# Output: all-reduced-function-counts.csv
#         row format = [file_name, [list of function names]...]
#
#
#
# Author: Derek Chadwick
# Date  : 14/11/2016
#
# TODO: optimise and many many things

import os
from csv import writer
import numpy as np
import pandas as pd
import math
import scipy.misc
import array
import re
from sklearn.feature_selection import SelectKBest, SelectPercentile
from sklearn.feature_selection import chi2


def reduce_column_names(column_names_file):
    # Reduce the number of column names, there are just too many.

    colf = open('data/' + column_names_file, 'r')
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


def get_training_labels(feature_set_file, train_label_file):
    # Load training labels
    sorted_train_labels = pd.read_csv("data/" + train_label_file, na_filter=False)
    #sorted_train_labels.head()
        
    # Load and sort the malware sample names.
    sample_names = pd.read_csv(feature_set_file, usecols = [0], na_filter=False)
    sorted_sample_names = sample_names.sort_values(by = 'filename')
    sample_list = list(sorted_sample_names['filename'])
    train_list = list(sorted_train_labels['file_name'])

    # Now get the labels of the PE malware samples from the label set.
    counter = 0
    y = []

    print("Sample list len = {:d} train list len = {:d}".format(len(sample_list), len(train_list)))

    for fname in sample_list:
        if fname.endswith('.elf'):
            print("ERROR: sample {:s} is an ELF binary.".format(fname)) # VS263 has five ELF samples in it, picked up from the call graph files
            continue                                                    # which must have had the ELF ASM files in the train3asm directory
                                                                        # during call graph generation.
        counter += 1
        if counter % 10000 == 1:
            print("Constructing y - Appending {:d} -> {:s}".format(counter, fname))
        for idx, fname2 in enumerate(train_list):
            if (fname2 == fname):
                y.append(sorted_train_labels.iloc[idx, 4]) # Append the family class label.
                break
    
    ###############################
    # DEPRECATED: Write out the PE/COFF sample train labels for later use and validation.
    #fop = open('data/' + temp_train_labels, 'w')
    #fop.writelines("\n".join(str(x) for x in y))
    #fop.close()
    ###############################


    # Now check the dimension consistency.
    for fname in sample_list:
        if fname not in train_list:
            print("ERROR: {:s} sample name not in train label set.".format(fname))
    

    return y



def reduce_feature_set(feature_set_file, train_label_file, function_name_file, column_names_file, subsets):
    # Use chi2 tests to determine the 10% best features see (mmmc/feature-reduction-call-graphs.ipynb).
    # Ok, so we still have 100000+ features even after severely reducing the function name lengths.
    # This is a problem. Having to process such a huge sparse matrix requires a lot of memory.
    # Solution 1: rent an AWS server with plenty-o-ram. (costs money and requires high bandwidth for file transfer)
    # Solution 2: buy more RAM for the linux box. (costs money)
    # Solution 3: break the sparse matrix into smaller chunks and process individually. (Ok)
    # Solution 4: try the pandas sparse matrix data structure. (too slow)
    
    # -> Solution 3: slice the matrix into smaller chunks for processing.
    # the pandas spare matrix still takes too long, break the feature set into 10 different feature subsets and try again.
    
    # Procedure:
    # 1. Open the PE function count feature file.
    # 2. Open the PE function name file and get the number of column names.
    # 3. Divide the number of columns by 10 to get the column subset length.
    # 4. Load the malware label set.
    # 5. Use pandas to load and sort each column subset.
    # 6. Do the chi2 tests to reduce each column subset to 10 percent best features.
    # 7. Recombine the column subsets.
    # 8. Perform the chi2 test again on the combined reduced feature set.
    # 9. Write out the final reduced feature set to a csv file.
    
    # Open PE function name file and get a list of token names.
    
    all_column_names = reduce_column_names(column_names_file)
    col_names_len = len(all_column_names)
    feature_column_names = all_column_names[1:] # Skip the "filename" column.
 

    # Now get the labels of the PE malware samples from the label set.
    counter = 0
    y = get_training_labels(feature_set_file, train_label_file)
    len_y = len(y)
    print("Got {:d} training labels.".format(len_y)) 
    
    # Load column subset and sort, then 
    # Perform chi2 test to get 10% best features.
    
    subset_len = int(col_names_len / subsets) 
    startidx = 1 # skip the filename column
    endidx = subset_len

    for idx in range(0, subsets):
        print("Processing function count column set {:d} -> {:d}".format(startidx, endidx))
        filename = "data/pe-function-count-temp-" + str(idx) + "-10perc.csv"
        # Resume after a nasty out of memory error.
        if os.path.isfile(filename):
            startidx = endidx
            endidx += subset_len
            print("{:s} exists, continuing.".format(filename))
            continue

        column_numbers = [ 0 ] + list(range(startidx, endidx, 1))
        feature_subset = pd.read_csv(feature_set_file, usecols = column_numbers, na_filter=False)
        
        # Sort the feature subset on file_name column.
        sorted_feature_subset = feature_subset.sort_values(by = 'filename')
        
        X = sorted_feature_subset.iloc[:,1:] # skip the filename, get the family class label for this feature subset.

        # Find the top 10 percent variance features.
        print("Sorted feature subset - slice {:d} of {:d}.".format(idx, subsets))
        print("Subset shape: {:d} {:d}".format(X.shape[0], X.shape[1]))
        print("Length of y: {:d}".format(len_y))
        #sorted_feature_subset.head()
        
        # Now select the 10% best features for this feature subset.
        fsp = SelectPercentile(chi2, 10)
        X_new_10 = fsp.fit_transform(X,y)
        selected_names = fsp.get_support(indices=True)
        selected_names = selected_names + 1 # the column name indices start at 0 so add 1 to all.
        
        data_trimmed = sorted_feature_subset.iloc[:,selected_names]
        data_fnames = pd.DataFrame(sorted_feature_subset['filename'])
        data_reduced = data_fnames.join(data_trimmed)
        
        # Write to file as we do not have enough memory.
        data_reduced.to_csv(filename, index=False)

        del(data_reduced)
        del(data_trimmed)
        del(data_fnames)
        
        # TEST AND VALIDATION ONLY.
        ############################################
        #out_subset = sorted_feature_subset.iloc[:,0:2]
        #out_subset.to_csv(filename, index=False)
        print("Writing reduced feature file: {:s}".format(filename))
        ############################################
        
        startidx = endidx
        endidx += subset_len


    return


def combine_reduced_feature_sets(reduced_feature_file_name, subsets):
    # Now recombine the reduced subsets and perform chi-squared tests again.
    fname = "data/pe-function-count-temp-0-10perc.csv"
    reduced_feature_counts = pd.read_csv(fname)
    for idx in range(1, subsets):
        fname = "data/pe-function-count-temp-" + str(idx) + "-10perc.csv"
        print("Processing file: {:s}".format(fname))
        nextfc = pd.read_csv(fname)
        reduced_feature_counts = pd.merge(reduced_feature_counts, nextfc, on='filename')


    reduced_feature_counts.to_csv("data/" + reduced_feature_file_name, index=False)
    print("Saved reduced feature set: {:d} {:d}".format(reduced_feature_counts.shape[0], reduced_feature_counts.shape[1]))
    
    return


def final_feature_set_reduction(reduced_feature_file_name, final_file_name, train_label_file):
    sorted_train_data = pd.read_csv('data/' + reduced_feature_file_name)
    y = get_training_labels('data/' + reduced_feature_file_name, train_label_file)
    X = sorted_train_data.iloc[:,1:]

    print("Final feature reduction: {:s}".format(reduced_feature_file_name))
    print("Training labels length: {:d}".format(len(y)))
    print("X Feature set dimensionality: {:d} {:d}".format(X.shape[0], X.shape[1]))
    print("In Feature set dimensionality: {:d} {:d}".format(sorted_train_data.shape[0], sorted_train_data.shape[1]))

    # find the top 10 percent variance features, from ~1000 -> ~100 features
    fsp = SelectPercentile(chi2, 10)
    X_new_10 = fsp.fit_transform(X,y)
    print("Final 10 Percent Dimensions: {:d} {:d}".format(X_new_10.shape[0], X_new_10.shape[1]))
    
    selected_names = fsp.get_support(indices=True)
    selected_names = selected_names + 1

    #data_reduced = sorted_train_data.iloc[:,[0] + selected_names]
    #Does not put the file_name as the first column.
    data_trimmed = sorted_train_data.iloc[:,selected_names]
    data_fnames = pd.DataFrame(sorted_train_data['filename'])
    data_reduced = data_fnames.join(data_trimmed)
    
    data_reduced.to_csv('data/' + final_file_name, index=False)
    print("Completed reduction in {:s}".format(final_file_name))
    
    return



# Start of Script.
if __name__ == "__main__":

    ext_drive = '/opt/vs/'
    feature_set = 'vs263'
    number_of_subsets = 30 # Make it variable, increase to reduce memory exhaustion errors.

    feature_file = ext_drive + 'call-graph-reduced-function_counts-' + feature_set + '-clean.csv'
    reduced_feature_file = 'reduced-function-counts-' + feature_set + '.csv'
    function_names_file = 'all-column-names-multi-line-' + feature_set + '.txt'
    training_labels_file = 'sorted-train-labels-' + feature_set + '.csv'
    final_file_name = 'sorted-pe-function-count-features-10percent-' + feature_set + '.csv'

    reduce_feature_set(feature_file, training_labels_file, function_names_file, function_names_file, number_of_subsets)

    combine_reduced_feature_sets(reduced_feature_file, number_of_subsets)

    final_feature_set_reduction(reduced_feature_file, final_file_name, training_labels_file)

# End of Script.

# feature_reduction_pe_header.py
#
# Read a PE/COFF header feature file and use chi-squared tests to remove features
# that are independent of the label. Features include PE section names, 
# imported DLL names, imported function names, exported function names etc.
#
# Output: sorted-pe-header-features.csv
#         row format = [file_name, [keyword list...]]
#
# Output: sorted-pe-header-features-reduced.csv
#         row format = [file_name, [keyword list...]]
#
#
#
# Author: Derek Chadwick
# Date  : 30/09/2016
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



def reduce_feature_set(feature_set_file, train_label_file, token_file, reduced_set_file, temp_train_labels):
    # Use chi2 tests to determine the 10% best features see (mmmc/feature-reduction-call-graphs.ipynb).
    # Ok, so we still have 100000+ features even after severely reducing the function name lengths.
    # This is a problem. Having to process such a huge sparse matrix requires a lot of memory.
    # Solution 1: rent an AWS server with plenty-o-ram. (costs money and requires high bandwidth for file transfer)
    # Solution 2: buy more RAM for my linux box. (costs money)
    # Solution 3: break the sparse matrix into smaller chunks and process individually. (Ok)
    # Solution 4: try the pandas sparse matrix data structure. (too slow)
    
    # -> Solution 3: slice the matrix into smaller chunks for processing.
    # the pandas spare matrix still takes too long, break up into 10 different feature sets and try again.
    
    # Procedure:
    # 1. Open the PE header feature file.
    # 2. Open the PE header token file and get the number of column names.
    # 3. Divide the number of columns by 10 to get the column subset length.
    # 4. Load the malware label set.
    # 5. Use pandas to load and sort each column subset.
    # 6. Do the chi2 tests to reduce each column subset to 10 percent best features.
    # 7. Recombine the column subsets.
    # 8. Perform the chi2 test again on the combined reduced feature set.
    # 9. Write out the final reduced feature set to a csv file.
    
    # Open PE header token file and get a list of token names.
    hdr_pd = pd.read_csv('data/' + token_file, na_filter=False) # Do not do NaN filtering or we will get floats instead of text.
    token_list = list(hdr_pd['token_name'])
    token_list_len = len(token_list)
    for idx, token in enumerate(token_list): # Clamp the token name length and demangle C++ names, they are annoying.
        #token = token.replace('@','').replace('$','').replace('?','')
        if len(token) > 32:
            token_list[idx] = token[:32]
        else:
            token_list[idx] = token
    
    # Load training labels
    sorted_train_labels = pd.read_csv("data/" + train_label_file)
    #sorted_train_labels.head()
        
    # Load and sort the malware sample names.
    sample_names = pd.read_csv(feature_set_file, usecols = [0], na_filter=False)
    sorted_sample_names = sample_names.sort('file_name')
    
    # Now get the labels of the PE malware samples from the label set.
    counter = 0
    y = []
    #train_names = sorted_train_labels['family_label']
    for fname in sorted_sample_names['file_name']:
        counter += 1
        if counter % 10000 == 1:
            print("Appending {:d} -> {:s}".format(counter, fname))
        for idx, fname2 in enumerate(sorted_train_labels['file_name']):
            if (fname2 == fname):
                y.append(sorted_train_labels.iloc[idx, 4]) # Append the family class label.
                break
    
    ###############################
    # Write out the PE/COFF sample train labels for later use and validation.
    fop = open('data/' + temp_train_labels, 'w')
    fop.writelines("\n".join(str(x) for x in y))
    fop.close()
    ###############################
    
    # Load column subset and sort, then 
    # Perform chi2 test to get 10% best features.
    
    onetenth = int(token_list_len / 10)
    startidx = 1 # skip the filename column
    endidx = onetenth

    for idx in range(0,10):
        print("Processing column set {:d} -> {:d}".format(startidx, endidx))
        column_numbers = [ 0 ] + list(range(startidx, endidx, 1))
        feature_subset = pd.read_csv(feature_set_file, usecols = column_numbers)
        
        # Sort the feature subset on file_name column.
        sorted_feature_subset = feature_subset.sort('file_name')
        
        X = sorted_feature_subset.iloc[:,1:] # skip the filename, get the family class label for this feature subset.

        # Find the top 10 percent variance features.
        print("Sorted feature subset - slice {:d} of 10.".format(idx))
        print("Subset shape: {:d} {:d}".format(X.shape[0], X.shape[1]))
        print("Length of y: {:d}".format(len(y)))
        #sorted_feature_subset.head()
        
        # Now select the 10% best features for this feature subset.
        # Try to make the subset file sizes smaller.
        fsp = SelectPercentile(chi2, 10)
        X_new_10 = fsp.fit_transform(X,y)
        selected_names = fsp.get_support(indices=True)
        selected_names = selected_names + 1 # the column name indices start at 0 so add 1 to all.
        
        data_trimmed = sorted_feature_subset.iloc[:,selected_names]
        data_fnames = pd.DataFrame(sorted_feature_subset['file_name'])
        data_reduced = data_fnames.join(data_trimmed)
        
        # Write to file as we do not have enough memory.
        filename = "data/pe-header-temp-" + str(idx) + "-10perc.csv"
        data_reduced.to_csv(filename, index=False)
        
        # TEST AND VALIDATION ONLY.
        ############################################
        #out_subset = sorted_feature_subset.iloc[:,0:2]
        #out_subset.to_csv(filename, index=False)
        print("Writing reduced feature file: {:s}".format(filename))
        ############################################
        
        startidx = endidx
        endidx += onetenth


    return


def combine_reduced_feature_sets(reduced_feature_file_name):
    # Now recombine the reduced sets and perform chi-squared tests again.
    fname = "data/pe-header-temp-0-10perc.csv"
    reduced_feature_counts = pd.read_csv(fname)
    for idx in range(1,10):
        fname = "data/pe-header-temp-" + str(idx) + "-10perc.csv"
        print("Processing file: {:s}".format(fname))
        nextfc = pd.read_csv(fname)
        reduced_feature_counts = pd.merge(reduced_feature_counts, nextfc, on='file_name')


    reduced_feature_counts.to_csv("data/" + reduced_feature_file_name, index=False)
    print("Saved reduced feature set: {:d} {:d}".format(reduced_feature_counts.shape[0], reduced_feature_counts.shape[1]))
    
    return


def final_feature_set_reduction(reduced_feature_file_name, final_file_name, train_label_file):
    sorted_train_data = pd.read_csv('data/' + reduced_feature_file_name)
    y = []
    X = sorted_train_data.iloc[:,1:]
    fip = open('data/' + train_label_file)
    lines = fip.readlines()
    for line in lines:
        line = line.rstrip()
        y.append(int(line))

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
    data_fnames = pd.DataFrame(sorted_train_data['file_name'])
    data_reduced = data_fnames.join(data_trimmed)
    
    data_reduced.to_csv('data/' + final_file_name, index=False)
    print("Completed reduction in {:s}".format(final_file_name))
    
    return



# Start of Script.
if __name__ == "__main__":

    #ext_drive = '/opt/vs/'
    #feature_file = ext_drive + 'pe-header-features-vs251.csv'
    #reduced_feature_file = 'pe-header-features-reduced-vs251.csv'
    #token_names_file = 'pe-header-tokens-vs251.csv'
    #training_labels_file = 'sorted-train-labels-vs251.csv'
    #temp_train_labels_file = 'pe-train-labels-vs251.txt'
    #final_file_name = 'sorted-pe-header-features-reduced-10percent-vs251.csv'

    #####################################################
    # NOTE: there is a problem with the vs252 feature file, need to redo the feature extraction.
    #       see feature_extraction_pe_header.py
    #
    ext_drive = '/opt/vs/'
    feature_file = ext_drive + 'pe-header-features-vs252.csv'
    reduced_feature_file = 'pe-header-features-reduced-vs252.csv'
    token_names_file = 'pe-header-tokens-vs252.csv'
    training_labels_file = 'sorted-train-labels-vs252.csv'
    temp_train_labels_file = 'pe-train-labels-vs252.txt'
    final_file_name = 'sorted-pe-header-features-10percent-vs252.csv'
    #####################################################

    #ext_drive = '/opt/vs/'
    #feature_file = ext_drive + 'pe-header-features-vs263-clean.csv'
    #reduced_feature_file = 'pe-header-features-reduced-vs263.csv'
    #token_names_file = 'pe-header-tokens-vs263.csv'
    #training_labels_file = 'sorted-train-labels-vs263.csv'
    #temp_train_labels_file = 'pe-train-labels-vs263.txt'
    #final_file_name = 'sorted-pe-header-features-10percent-vs263.csv'

    #ext_drive = '/opt/vs/'
    #feature_file = ext_drive + 'pe-header-features-vs264-clean.csv'
    #reduced_feature_file = 'pe-header-features-reduced-vs264.csv'
    #token_names_file = 'pe-header-tokens-vs264.csv'
    #training_labels_file = 'sorted-train-labels-vs264.csv'
    #temp_train_labels_file = 'pe-train-labels-vs264.txt'
    #final_file_name = 'sorted-pe-header-features-10percent-vs264.csv'

    #######################################################
    # NOTE: there is also a problem with vs263 and vs264 
    #       feature sets, all the rows are zeroes!!!.
    #######################################################

    reduce_feature_set(feature_file, training_labels_file, token_names_file, reduced_feature_file, temp_train_labels_file)

    combine_reduced_feature_sets(reduced_feature_file)

    final_feature_set_reduction(reduced_feature_file, final_file_name, temp_train_labels_file)

# End of Script.


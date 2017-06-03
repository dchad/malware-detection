# feature_reduction_pe_asm.py
#
# Read a bunch of PE feature files and use chi-squared tests to remove features
# that are independent of the label.
#
# Feature sets include:
#
# Input : sorted-pe-asm-features.csv
#         row format = [file_name, [list of x86 opcodes], [list of x86 registers]]
#          
#         sorted-pe-header-features.csv
#         row format = [file_name, [keyword list...]]
#
#         sorted-pe-call-graph-features.csv
#         row format = [file_name, [function name list...]]
#
#         sorted-packer-id-features.csv
#         row format = [file_name, packer_name, packer_id, valid_pe, is_packed]]
#
#         sorted-file-id-features.csv
#         row format = [file_name, file_type, file_id]
#
#         sorted-trid-id-features.csv
#         row format = [file_name, file_type, percentage, trid_id]
#
#         sorted-entropy-features.csv
#         row format = [file_name, entropy, file_size]
#
# Output: sorted-pe-asm-features-reduced.csv
#         row format = [file_name, [list of x86 opcodes], [list of x86 registers]]
#
#
#
# Author: Derek Chadwick
# Date  : 30/09/2016
#
# TODO: optimise and many many things

import numpy as np
import scipy as sp
import pandas as pd
import sklearn as skl
import matplotlib.pyplot as plt
from sklearn.feature_selection import SelectKBest, SelectPercentile
from sklearn.feature_selection import chi2
from sklearn.metrics import log_loss, confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.cross_validation import cross_val_score, KFold




def feature_reduction_percent(percentage, train_data_df, train_labels_df):
    # TODO: everythong
    X = train_data_df.iloc[:,1:]
    y = np.array(train_labels_df.iloc[:,1])

    # find the top percent variance features.
    fsp = SelectPercentile(chi2, percentage)
    
    X_reduced = fsp.fit_transform(X,y)
    selected_names = fsp.get_support(indices=True)
    selected_names = selected_names + 1
    data_trimmed = sorted_train_data.iloc[:,selected_names]
    data_fnames = pd.DataFrame(sorted_train_data['filename'])
    data_reduced = data_fnames.join(data_trimmed)
    data_reduced.to_csv('data/sorted-train-malware-features-asm-50percent.csv', index=False)

    return
    

def combine_feature_sets(feature_set_name)
    # First load the training data feature sets and training labels
    sorted_pe_asm = pd.read_csv("data/sorted-pe-asm-features-" + feature_set_name + ".csv")
    sorted_pe_hdr = pd.read_csv("data/sorted-pe-header-features-" + feature_set_name + ".csv")
    sorted_pe_call_graph = pd.read_csv("data/sorted-pe-call-graph-features-" + feature_set_name + ".csv")
    sorted_packer_id = pd.read_csv("data/sorted-packer-id-features-byte-" + feature_set_name + ".csv")
    sorted_file_id = pd.read_csv("data/sorted-file-id-features-byte-" + feature_set_name + ".csv")
    sorted_trid_id = pd.read_csv("data/sorted-trid-id-features-byte-" + feature_set_name + ".csv")
    sorted_entropy = pd.read_csv("data/sorted-entropy-features-byte-" + feature_set_name + ".csv")
    
    sorted_train_labels = pd.read_csv("data/sorted-train-labels-" + feature_set_name + ".csv")

    # Combine all the training features and write to file.
    combined_train_data = sorted_pe_asm.merge(sorted_pe_hdr, on='file_name')
    combined_train_data = combined_train_data.merge(sorted_pe_call_graph, on='file_name')
    combined_train_data = combined_train_data.merge(sorted_packer_id, on='file_name', suffixes=('_A', '_I'))
    combined_train_data = combined_train_data.merge(sorted_file_id, on='file_name')
    combined_train_data = combined_train_data.merge(sorted_trid_id, on='file_name')
    combined_train_data = combined_train_data.merge(sorted_entropy, on='file_name')
    combined_train_data.to_csv("data/final-combined-train-data-" + feature_set_name ".csv", index=False)


    return combined_train_data


# Start of Script
if __name__ == "__main__":

    sorted_train_data = pd.read_csv('data/sorted-pe-asm-features-vs251.csv')
    sorted_labels = pd.read_csv('data/sorted-train-labels-vs251.csv')



# End of Script

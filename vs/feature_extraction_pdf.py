# feature_extraction_pdf.py
#
# Read a list of PDF files and extract
# feature sets from them.
#
# Input: target directory containing the sample files.
#        PDF token names file -> (from generate_pdf_tokens.py)
#
# Output: PDF object counts in CSV format.
#         row format = ['file_name', ['list of token names', ...]]
#
# Author: Derek Chadwick
# Date  : 05/09/2016
#
# TODO: all of the things


import os
from csv import writer
import numpy as np
import pandas as pd


def count_pdf_keywords(content, keywords, klen):
    
    keywords_values = [0] * klen
    
    for row in content:
        for i in range(klen):
            if keywords[i] in row:
                keywords_values[i] += 1
                break
                
    return keywords_values



def extract_pdf_features(multi_parameters):
    # 1. Get the feature file and token/keyword file names
    # 2. Create an array of token/keyword values.
    # 3. Iterate throught the PDF file list and counter the occurrence of the keywords in each file.

    pid = os.getpid()
    feature_file = 'data/' + str(pid) + "-" + multi_parameters.out_file  
    token_file = 'data/' + multi_parameters.token_file
    pdf_files = multi_parameters.file_list
    
    print('Process id: {:d} - Feature file: {:s} - Keyword file: {:s}'.format(pid, feature_file, token_file))

    hdr_pd = pd.read_csv(token_file)
    tokens = list(hdr_pd['token_name'])
    tlen = len(tokens)
    ftot = len(pdf_files)
    
    feature_counts = []
    with open(feature_file, 'w') as f:

        fw = writer(f)
        fw.writerow(['file_name'] + tokens)
        
        for idx, fname in enumerate(pdf_files):
            
            fasm = open(fname, 'r')
            content = fasm.readlines()
            fasm.close()

            #print("Debug in -> {:s}".format(fname))
            
            #fname = fname[fname.find("_")+1:] 
            # Remove VirusShare_ from the start of the file name.
            
            keyword_vals = count_pdf_keywords(content, tokens, tlen)
            
            #feature_counts.append([fname[0:fname.find('.pe.txt')]] + keyword_vals)   
            feature_counts.append([fname] + keyword_vals)
            
            # Writing rows after every 10 files processed
            if (idx+1) % 10 == 0:
                print("{:d} - {:d} of {:d} files processed.".format(pid, idx + 1, ftot))
                fw.writerows(feature_counts)
                feature_counts = []
                
            #print("Debug out -> {:s}".format(fname))

        # Writing remaining features
        if len(feature_counts) > 0:
            fw.writerows(feature_counts)
            feature_counts = []

    print("{:d} Completed processing {:d} PDF files.".format(pid, ftot))
                      
    return



class Multi_Params(object):
    def __init__(self, outfile="", tokenfile="", filelist=[]):
        self.out_file = outfile
        self.token_file = tokenfile
        self.file_list = filelist
        
        
        
        
# Start of Script

target_dir = "/opt/vs/pdfset/"
out_file = "pdf-features-legit.csv"
pdf_token_file = "2716-pdf-token-counts-non-malicious-set.csv"
#out_file = "data/pdf-features-vs251.csv"

 

file_list = os.listdir(target_dir)

pdflist = []

for fname in file_list:
    if fname.endswith('.pdf'):
        pdflist.append(target_dir + fname)
    
print("Got {:d} PDF files.".format(len(pdflist)))

mp1 = Multi_Params(out_file, pdf_token_file, pdflist)

extract_pdf_features(mp1)

# End of Script

# combine-av-reports.py
#
# Combine the processed ClamAV and Windows Defender reports, drop duplicates and 
# fill NaN values with "OK".
#
# Inputs : clamav-xxx.csv and defender-xxx.csv
#          row format = [file_name, malware_type]
#
# Outputs: sorted-av-report.csv
#          row format = [file_name, clamav_malware_type, windefender_malware_type] 
#
#          
#
# Author: Derek Chadwick
# Date  : 18/08/2016

import os
import pandas as pd
import numpy as np



def combine_av_reports(av_file_1, av_file_2, out_file):
    mals1 = pd.read_csv(av_file_1)
    mals2 = pd.read_csv(av_file_2)

    allmals = mals1.merge(mals2, on='filename', how='outer', indicator=True, sort=True)

    uniq_allmals = allmals.drop_duplicates(subset='filename', keep='first')

    filled_uniq_allmals = uniq_allmals.replace(np.NaN, 'OK')

    # Now we have our combined AV results, write to file.
    filled_uniq_allmals.to_csv(out_file, index=False)
    
    return


# TODO: Add command line arguments to specify files to combine and output file.

# Start of Script

clammals = pd.read_csv('data/clamav-vs263-264-apt.csv')
windefmals = pd.read_csv('data/defender-vs263-264-apt.csv')

print("Read {:d} ClamAV detections.".format(clammals.shape[0]))
print("Read {:d} Windows Defender detections.".format(windefmals.shape[0]))

# allmals = clammals.merge(windefmals, on='filename', how='outer', indicator=True, sort=True)
# NOTE: old versions of pandas merge() do not have indicator argument.

allmals = clammals.merge(windefmals, on='filename', how='outer', sort=True)

# uniq_allmals = allmals.drop_duplicates(subset='filename', keep='first')
# NOTE: old versions of pandas do not have subset argument in drop_duplicates()
#       or keep argument.

uniq_allmals = allmals.drop_duplicates(cols='filename', take_last=False)

filled_uniq_allmals = uniq_allmals.replace(np.NaN, 'OK')

# Now we have our combined AV results, write to file.
filled_uniq_allmals.to_csv('data/sorted-av-report.csv', index=False)

print("Wrote {:d} combined malware detections.".format(filled_uniq_allmals.shape[0]))

# End of Script


# analyze.py
#
# Analyse a PE/COFF malware sample or directory of samples and generate a report.
#
# Inputs : Path to a filename or directory.
#
#
# Outputs: report.csv
#          row format = [file_name, clamav_malware_type, packed_exe, file_entropy, decision, confidence_level] 
#
#          
# 1. Get file entropy and file size.
# 2. Get file id and trid id.
# 3. Get clamav report.
# 4. Disassemble with objdump or 
# 5. Extract ASM features.
# 6. Extract PE Header features.
# 7. Reduce PE Header features.
# 8. Generate call graph and features.
# 9. Generate function counts.
# 10. Reduce function counts.
# 11. Apply model stack.
# 12. Generate report.
#
# Author: Derek Chadwick
# Date  : 18/05/2017

import sys
import os
import pandas as pd
import numpy as np





if __name__ == "__main__":
    
    
    filename = sys.argv[1]
    if os.path.isfile(filename):


    else:
    

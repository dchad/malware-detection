# malware-detection

Experiments in malware detection and classification using machine learning techniques.

## 1. Microsoft Malware Classification Challenge

    https://www.kaggle.com/c/malware-classification
    
### 1.1 Feature Engineering

    Initial feature engineering consisted of extracting various keyword counts from the ASM files 
    as well as the entropy and file size from the BYTE files of the 10868 malware samples in the training set. 
    Image files of the first 1000 bytes of the ASM and BYTE files were created and combined with 
    keyword and entropy data. This resulted in a set of 2018 features.
    Flow control graphs and call graphs were generated for each ASM sample. A feature set was
    then generated from the graphs, including graph maximum delta, density, diameter and function
    counts etc.
    
### 1.2 Feature Selection

    Statistical analysis of the feature set using chi-squared tests to remove features that are 
    independent of the class labels or have low variance. The BYTE file images were found to be weak
    learners and were removed from the feature set. A comparison of the best features from the chi-squared
    tests with reduced feature sets of between 10% - 50% of the original features.
    
#### 1.2.1 Selection Comparison

    Testing with an ExtraTreesClassifier and 10-fold cross validation produced the following results:
    - Original ASM Keyword Counts (1006 features): logloss = 0.034
    - 10% Best ASM Features with Entropy and Image Features (202 features): logloss = 0.0174
    - 20% Best ASM with Entropy and Image Features (402 features): logloss = 0.0164
    - 30% Best ASM with Entropy and Image Features plus Feature Statistics (623 features): 
      multiclass logloss = 0.0133
      accuracy score = 0.9978
      Confusion Matrix:
      [[1540    0    0    0    0    1    0    0    0]
      [   1 2475    2    0    0    0    0    0    0]
      [   0    0 2942    0    0    0    0    0    0]
      [   1    0    0  474    0    0    0    0    0]
      [   2    0    0    0   38    2    0    0    0]
      [   3    0    0    0    0  748    0    0    0]
      [   1    0    0    0    0    0  397    0    0]
      [   0    0    0    0    0    0    0 1225    3]
      [   0    0    0    0    0    0    0    8 1005]]
    - 40% Best ASM and image features with feature statistics:
      ExtraTreesClassifier with 1000 estimators on 10868 training samples and 823 features 
      using 10-fold cross validation:
        multiclass logloss = 0.0135
        accuracy score = 0.9976
        Confustion Matrix:
        [[1541    0    0    0    0    0    0    0    0]
        [   1 2475    2    0    0    0    0    0    0]
        [   0    0 2942    0    0    0    0    0    0]
        [   1    0    0  474    0    0    0    0    0]
        [   5    0    0    0   37    0    0    0    0]
        [   5    0    0    0    0  746    0    0    0]
        [   1    0    0    0    0    0  397    0    0]
        [   0    0    0    0    0    0    0 1227    1]
        [   0    0    0    0    0    0    0    9 1004]]
        
#### 1.2.2 Feature Selection Summary

     The performance of the ExtraTreesClassifier is optimal at around 30% of ASM and image features 
     with highest variance plus sample statistics, entropy and file size. Adding call graph features
     produced a marginal improvement. It is possible that better classification accuracy would be
     achieved by using an ensemble of different classifiers with the ASM, image and call graph
     feature sets as separate inputs to the various classifiers.
     
### 1.3 Model Selection

    Selection of candidate models using GridSearchCV to find optimal classifier hyper-parameters. 
    - SVM:
    - ExtraTrees:
    - XGBoost: 30% Best Features
               logloss: 0.0080
               accuracy: 0.9981
               Confusion Matrix:
               [[1540    0    0    0    0    1    0    0    0]
                [   2 2475    0    1    0    0    0    0    0]
                [   0    0 2941    0    0    0    1    0    0]
                [   0    0    0  474    0    1    0    0    0]
                [   1    0    0    0   41    0    0    0    0]
                [   4    0    0    0    1  746    0    0    0]
                [   0    0    0    0    0    0  398    0    0]
                [   0    0    0    0    0    0    0 1227    1]
                [   0    0    0    0    0    0    0    8 1005]]               
    - NaiveBayes:
    - KNN:
### 1.4 Graphs

!["File Entropy Graph 1"](https://github.com/dchad/malware-detection/blob/master/resources/file-entropy-by-class.png "File Entropy by Malware Class")
         1. Shannon's Entropy by malware class. A score of 0.0 means the bytes are all the same value, 
            a score of 1.0 means every byte in the file has a different value.
            
            
!["File Entropy Graph 2"](https://github.com/dchad/malware-detection/blob/master/resources/file-entropy-by-size.png "File Entropy by File Size")
         2. Shannon's Entropy by file size. A score of 0.0 means the bytes are all the same value, 
            a score of 1.0 means every byte in the file has a different value.
            
            
!["ASM Registry Counts"](https://github.com/dchad/malware-detection/blob/master/resources/register-counts.png "EDX by ESI Registry Counts")
         3. Assembler register EDX by ESI counts.
         
         
### 1.5 Conclusions

   The best accuracy scores were achieved with XGBoost (99.81%) and ExtraTreesClassifier (99.76%) using a 
   feature set of 623 ASM, image and entropy features. Marginal improvements could be achieved using additional
   features and ensemble methods, however due to the limited sample size further efforts are unlikely to produce 
   significant improvements in prediction accuracy. Analysis will now focus on much larger sample sizes from 
   VirusShare.com as described in the following sections.
   


### <<<=============================================================>>>



## 2. VirusShare.com Malware Collection Analysis

   VirusShare.com regularly publishes huge collections of malware binaries for use by researchers. 
   Each malware archive is currently around 25GB in size. Several of the latest archives have been 
   downloaded to use as training and test sets. The archives used are:
   
    - Training set: VirusShare_00251.zip and VirusShare_00252.zip (131072 malware samples)
                    VirusShare_00263.zip and VirusShare_00264.zip (131072 malware samples)
                    VirusShare_APT1_293.zip (293 malware samples)
    
    - Testing set: 
   
### 2.1 Automated Unpacking and Disassembly of Malware Binaries

    Using Cuckoo Sandbox and unpack.py for behaviourial analysis, unpacking the binaries and 
    dumping process memory, for intransigent samples, manual unpacking with Immunity Debugger and IDA Pro.
    
    Tools:
    
    - Cuckoo Sandbox (https://github.com/cuckoosandbox/cuckoo)
    
    - unpack.py (https://malwaremusings.com/2013/02/26/automated-unpacking-a-behaviour-based-approach/)
    
                (https://github.com/malwaremusings/unpacker)
                
    - IDA Pro 5.0 (https://www.hex-rays.com/products/ida/support/download_freeware.shtml)
    
    - Immunity Debugger (https://www.immunityinc.com/products/debugger/)
    
    - Volatility (https://github.com/volatilityfoundation)
    
    - Ildasm.exe (https://msdn.microsoft.com/en-us/library/f7dy01k1(v=vs.110).aspx)
    
    - ndisasm (http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/)
    
    - TrID (http://mark0.net/soft-trid-e.html)
    
    - ClamAV (clamav.net)
    
    - Windows Defender
    
    - MalwareBytes Anti-Malware
    
    - VirusTotal.com
    
    
#### Environment Setup (Debian):

    apt install virtualbox virtualbox-dkms python-dev libffi-dev virtualenv virtualenvwrapper clamav
    
    pip install cython numpy scipy scikit-learn matplotlib jupyter pandas xgboost
    
    git clone https://github.com/cuckoosandbox/cuckoo
    
    git clone https://github.com/volatility
    
    
#### Environment Setup (Windows):
    TODO:
    
    
### 2.2 Generating Training Labels

    ClamAV and Windows Defender used for initial training label generation or VirusTotal.com aggregate classification 
    if they cannot identify the culprit. MalwareBytes was also used but it crashed at the end of the scan
    and the log files could not be recovered.
    
    AV Scan Results:
    
    Results: VirusShare_00251
    
    - 57529 files classified as malicious.
    
    - 8007 files classified as non-malicious.
    
    Results: VirusShare_00252
    
    - 56625 files classified as malicious.
    
    - 8911 files classified as non-malicious.
    
    Results: VirusShare_00263
    
    - 51612 files classified as malicious.
    
    - 13924 files classified as non-malicious.
    
    Results: VirusShare_00264
    
    - 42274 files classified as malicious.
    
    - 23262 files classified as non-malicious.
    
    Results: VirusShare_APT1_293
    
    - 292 files classified as malicious.
    
    - 1 file classified as non-malicious.
    
    Total Malware Types: 8334
    
    Total Malware Families: 2737
    
    Total Files: 262437
    
    
#### 2.2.1 Graphs



!["Malware Counts"](https://github.com/dchad/malware-detection/blob/master/resources/malware-counts.png "Malware Counts")
         4. Top 10 Malware Counts.



!["Packer Counts"](https://github.com/dchad/malware-detection/blob/master/resources/packer-counts.png "Packer Counts")
         5. Top 10 Compiler/Packer Counts.
         
         

!["File Call Graph 1"](https://github.com/dchad/malware-detection/blob/master/resources/vs251-call-graph-vertex-by-edge-graph.png "VirusShare 251 PE/COFF Call Graph Vertext x Edge Count")
         6. VirusShare 251 Call Graph - Vertex by Edge Count.
            
         

!["File Histogram Graph 1"](https://github.com/dchad/malware-detection/blob/master/resources/vs251-entropy-histogram.png "File Entropy Histogram")
         7. VirusShare 251 Shannon's File Entropy Histogram.
    

    
### 2.3 Converting to ASM and Feature Extraction
    
    IDA Pro and objdump for disassembly of binaries to .asm text files.
    
    Feature sets will consist of:
    
    - Entropy and file size from packed binaries.
    
    - Entropy and file size from unpacked binaries.
    
    - File magic signatures and TrID signatures.
    
    - ASM features from disassembled unpacked binaries.
    
    - Executable header features.
    
    - Call Graph Features.
    
    - Function counts extracted from call graphs.
    
    - Sample Statistics.
    
    - Behavioural features from Cuckoo Sandbox reports.
    
    - Memory features from Volatility reports.
    
    
### 2.4 Feature Selection and Reduction

    1. PE/COFF Binaries: (Chi2 Tests)
                         VS251 Feature Sets: 54911 samples.
                                             240 PE ASM and Header Features.
                                             ?? PE ASM Function Count Features.
                                           
                         VS252 Feature Sets: 46165 samples.
                                             271 PE ASM and Header Features.
                                             ?? PE ASM Function Count Features.

                         VS263 Feature Sets: 40974 samples.
                                             203 PE ASM and Header Features.
                                             ?? PE ASM Function Count Features.

                         VS264 Feature Sets: 14366 samples.
                                             243 PE ASM and Header Features.
                                             ?? PE ASM Function Count Features.
    2. ELF Binaries:
    
    3. Java Bytecode:
    
    4. Javascript:
    
    5. HTML:
    
    6. PDF: 
    
    
### 2.5 Model Selection

#### 2.5.1 PE/COFF Model Selection
    
    Model selection with 10-fold cross validation:
    
    1. ExtraTreesClassifier: VS251 100 estimators accuracy score = 0.912
                                   500 estimators accuracy score = ?.??
                                   1000 estimators accuracy score = memory fail
                             VS252 100 estimators accuracy score = 0.888 (12.75 minutes)
                                   500 estimators accuracy score = ?.??
                                   1000 estimators accuracy score = ?.??
                             VS263 100 estimators accuracy score = 0.903 (9.63 minutes)
                                   500 estimators accuracy score = ?.???
                                   1000 estimators accuracy score = ?.??
                             VS264 100 estimators accuracy score = 0.889 (2.27 minutes)
                                   500 estimators accuracy score = 0.890 (14.57 minutes)
                                   1000 estimators accuracy score = ?.??
       
    2. XGBoost: VS251 100 estimators accuracy score = ?.??
       XGBoost: VS252 100 estimators accuracy score = ?.??
       XGBoost: VS263 100 estimators accuracy score = ?.??
       XGBoost: VS264 100 estimators accuracy score = ?.??
                      
    3. LightGBM: VS251 100 estimators accuracy score = 0.892
                 VS252 100 estimators accuracy score = 0.676 (171.23 minutes)
                 VS263 100 estimators accuracy score = ?.??
                 VS264 100 estimators accuracy score = 0.758 (9.26 minutes)
                       200 estimators accuracy score = 0.750 (18.53 minutes)
       
    4. RandomForestClassifier: VS251 100 estimators accuracy score = 0.903
                                     500 estimators accuracy score = ?.??
                                     1000 estimators accuracy score = ?.??
                               VS252 100 estimators accuracy score = 0.881 (81.34 minutes)
                               VS263 100 estimators accuracy score = ?.??
                               VS264 100 estimators accuracy score = 0.879 (15.45 minutes)
    


    Model Stacks/Ensembles:
    
        1. One input layer of classifiers -> 1 output layer classifier.
        
           Layer 1: Six x layer one classifiers: (ExtraTrees x 2, RandomForest x 2, XGBoost x 1, LightGBM x 1) 
           Layer 2: One classifier: (ExtraTrees) -> final labels
        
        2. Voting (Democratic and weighted).
        
           Democratic: Six x layer one classifiers: (ExtraTrees x 2/RandomForest x 2/XGBoost/LightGBM)
           -> (democratic vote, geometric and sum means) -> final labels
           
           Weighted: Six x layer one classifiers: (ExtraTrees x 2/RandomForest x 2/XGBoost/LightGBM)
           -> (weighted vote: ExtraTrees double weight, geometric and sum means) -> final labels
                           
        3. Multiple layers of classifiers.
    
           Layer one -> layer two -> layer 3 -> final labels:
           
           Layer 1: ExtraTrees x 2, RandomForest x 2, XGBoost x 1, LightGBM x 1
           Layer 2: ExtraTrees x 2, RandomForest x 2, XGBoost x 1, LightGBM x 1
           Layer 3: ExtraTrees x 1
    
        4. Combined PE/COFF features + function count features:
        
           Layer 1 -> layer 2 -> final labels
           
           Layer 1 (A MODELS): Combined features layer one (ExtraTrees x 2, RandomForest x 2, XGBoost x 1, LightGBM x 1)
           Layer 1 (B MODELS): Function count features layer one (ExtraTrees x 2, RandomForest x 2, XGBoost x 1, LightGBM x 1)
           
           Layer 2: ExtraTrees x 1 -> final labels
           
        5. Combine outputs from 1, 2, 3 and 4 -> vote -> final labels
        

#### 2.5.2 ELF Model Selection



#### 2.5.3 Java Bytecode Model Selection


#### 2.5.4 Javascript Model Selection

TODO:

    
### 2.6 Conclusions

    TODO:
    

### 2.7 Workflows

#### 2.7.1 Training Label Generation

    1. Antivirus scans using ClamAV and Windows Defender.
    
       > clamscan -v -r /directory/containing/the/nastiness > clamav-report.txt
       > Windows Defender (See notes in section 7 on extracting windows defender logs).
       
    2. Generate scalar training labels for each malware type and family.
    
       > process_av_reports.py
       > combine_av_reports.py
       > generate_train_labels.py
       
       
#### 2.7.2 Feature Engineering

##### 2.7.2.1 PE/COFF Malware Features

    1. File entropy feature generation.
       
       > feature_extraction_entropy.py
       
    2. File magic signature and TrID signature feature generation.
    
       > trid_check_file.py
       > generate_file_ids.py
       > feature_extraction_file_id.py
       
    3. Packer identification feature generation.
    
       > generate_packer_ids.py
       > feature_extraction_packer_id.py
       
    4. ASM feature generation (unpacked PE files).
    
       > disassemble_pe.py
       > feature_extraction_pe_asm.py
       > generate_pe_header_tokens.py
       > feature_extraction_pe_header.py
       
    5. ASM feature generation (packed PE files).
    
       > TODO:
       
    6. Call Graph Generation and feature extraction.
    
       > generate_call_graphs_pe_asm.py
       > generate_function_column_names.py
       > function_name_clean.py
       > feature_extraction_pe_function_counts.py
       > feature_reduction_pe_function_counts.py
       
    7. Behavioural analysis feature generation.
    
       > TODO:
       
    8. Memory analysis feature generation.
    
       > TODO:
       
##### 2.7.2.2 ELF Malware Features

    1. File entropy feature generation.
       
       > feature_extraction_entropy.py
       
    2. File magic signature and TrID signature feature generation.
    
       > trid_check_file.py
       > generate_file_ids.py
       > feature_extraction_file_id.py
       
    3. Packer identification feature generation.
    
       > generate_packer_ids.py
       > feature_extraction_packer_id.py
       
    4. ASM feature generation.
    
       > disassemble_elf.py
       > feature_extraction_elf_asm.py
       
    5. Call Graph Generation.
    
       >
       
    6. Behavioural analysis feature generation.
    
       >
       
    7. Memory analysis feature generation.
    
       >

##### 2.7.2.3 Java Bytecode Features

    1. Convert Bytecode to Tokens.

    2. Extract Bytecode Features.

    Tools: 

        javap (https://docs.oracle.com/javase/7/docs/technotes/tools/windows/javap.html)


##### 2.7.2.4 Javascript/HTML Features

    1. Generate Javascript/HTML Keywords.

    2. Unpack Javascript.

    3. Extract Javascript/HTML Features.

    Tools: 

        


##### 2.7.2.5 PDF Features

    1. Generate PDF Keywords.

    2. Extract Javascript/Shellcode/Macros.

    3. Extract PDF Feature Sets.

    Tools: 

        peepdf (https://github.com/jesparza/peepdf)

        

#### 2.7.3 Feature Selection
##### 2.7.3.1 PE/COFF Feature Selection

    1. PE/COFF Feature Reduction.
    
        > feature_reduction_pe_asm.py
        > feature_reduction_pe_header.py
        > feature_reduction_pe_function_counts.py
        
        
     
#### 2.74 Model Selection
TODO:

    1. PE/COFF Model Selection.
    
        > model_selection_pe_coff.py
        

## <<<========================================================>>>


       
## 3. Automated Sensor Malware Detection
TODO:



## 4. References
TODO:



## 5. Notes on installing xgboost for Python.

### 5.1 Source Install.

 If installing from source, after building and installing you have
 problems loading other packages it is because of the xgboost-0.4-py2.7.egg.pth
 file that the install script dumps in the python dist-packages
 directory. You will have to delete the .pth file then
 go change the installation of the xgboost egg and egg-info files in the 
 python dist-packages directory from:

 /usr/local/lib/python2.7/dist-packages/xgboost-0.4-py2.7.egg/EGG_INFO

 to:

 /usr/local/lib/python2.7/dist-packages/xgboost-0.4-py2.7.dist-info

 and: 

 /usr/local/lib/python2.7/dist-packages/xgboost-0.4-py2.7.egg/xgboost

 to:

 /usr/local/lib/python2.7/dist-packages/xgboost

 Now python will be able to find all the packages.
 
### 5.2 Pip Install. 

 pip install xgboost
 
 Now works for version 0.6a2 on Debian/Ubuntu/Mint distros.
 
 
### 5.3 Anaconda Install.

 XGBoost is not a part of the official distribution but several 
 community members have created Conda packages for it. The
 most up to date package seems to be by user creditx. The following
 command will install the package:

 conda install -c creditx xgboost
 
 
## 6. Notes on Installing Cuckoo Sandbox

  Python 2.7 is preferred for Cuckoo Sandbox, attempting with Python 3.x will be a fail.
  Installing the Python module requirements in requirements.txt results in failure because
  the module dpkt is only compatible with Python 2.x versions. If using Anaconda or python 3.x
  then revert to Python 2.7 or use mkvirtualenv to create a virtual environment to run cuckoo.
  
  For example:
  
  mkvirtualenv -p /usr/bin/python cuckoosandbox
  
  Note: If using Anaconda:
        Remove the Anaconda bin directory from $PATH or it will cause an error when setting
        up the virtual environment. Also ensure that libxml2-dev and libxslt1-dev are 
        installed or there will be build errors when installing the requirements.
     

        
## 7. Notes on Extracting Windows Defender Logs
 
     Open a powershell - (Run as Administrator).

     Enter the following commands:

     > cd \Program Files\Windows Defender

     > .\MpCmdRun -getfiles -scan
     
     Several .log and .cab files will be placed in:
     
     C:\ProgramData\Microsoft\Windows Defender\Support\
     
     The Windows Defender malware detection log is called MPDetection-yymmdd-hhmm.log


     
## 8. Notes on Multi-Architecture Disassembly with objdump

    Ensure binutils multi-target support has been installed (Linux Mint 18):
    (NOTE: Linux Mint 17 does not have MIPS architecture in binutils, have to install from sauce.)

    apt install binutils binutils-aarch64-linux-gnu binutils-alpha-linux-gnu binutils-arm-linux-gnueabi 
    binutils-arm-linux-gnueabihf binutils-arm-linux-gnueabihf binutils-arm-none-eabi binutils-avr binutils-dev 
    binutils-doc binutils-gold binutils-h8300-hms binutils-hppa-linux-gnu binutils-hppa64 binutils-hppa64-linux-gnu 
    binutils-m68hc1x binutils-m68k-linux-gnu binutils-mingw-w64 binutils-mingw-w64-i686 binutils-mingw-w64-x86-64 
    binutils-mips-linux-gnu binutils-mips64-linux-gnuabi64 binutils-mips64-linux-gnuabi64 binutils-mips64el-linux-gnuabi64 
    binutils-mips64el-linux-gnuabi64 binutils-mipsel-linux-gnu binutils-msp430 binutils-multiarch binutils-multiarch-dev 
    binutils-powerpc-linux-gnu binutils-powerpc-linux-gnuspe binutils-powerpc-linux-gnuspe binutils-powerpc64-linux-gnu 
    binutils-powerpc64-linux-gnu binutils-powerpc64le-linux-gnu binutils-powerpc64le-linux-gnu binutils-s390x-linux-gnu 
    binutils-sh4-linux-gnu binutils-source binutils-sparc64-linux-gnu binutils-z80 elf-binutils
    
    
    
## 9. Notes on Installing LightGBM

    1. Clone, build and install:
    
      git clone --recursive https://github.com/Microsoft/LightGBM
      cd LightGBM
      mkdir build
      cd build
      cmake ..
      make -j
      cd ../python-package/
      python setup.py install
    
    
    2. If you have problems with building or installing python module:
    
      apt update
      apt upgrade
      apt install cmake
      pip install setuptools numpy scipy scikit-learn -U
      

    3. If you have problems with updating setuptools, sklearn etc, and you probably will because (pip == train wreck):
 
      apt purge -y python-pip
      wget https://bootstrap.pypa.io/get-pip.py
      python ./get-pip.py
      apt install python-pip
      pip install setuptools numpy scipy scikit-learn -U



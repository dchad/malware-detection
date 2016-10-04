# feature_extraction_java.py
#
# Read a list of Java Bytecode files and extract
# feature sets from them.
#
# Input:
#
# Output:
#
# Author: Derek Chadwick
# Date  : 05/09/2016
#
# TODO: all of the things

from multiprocessing import Pool
import os
from csv import writer
import numpy as np
import pandas as pd
import math
import scipy.misc
import array
import time as tm
import re
import subprocess as sub


java_opcodes = ['aaload','aastore','aconst_null','aload','aload_0','aload_1','aload_2','aload_3',
               'anewarray','areturn','arraylength','astore','astore_0','astore_1','astore_2','astore_3',
                'athrow','baload','bastore','bipush','breakpoint','caload','castore','checkcast',
                'd2f','d2i','d2l','dadd','daload','dastore','dcmpg','dcmpl','dconst_0','dconst_1',
                'ddiv','dload','dload_0','dload_1','dload_2','dload_3','dmul','dneg','drem','dreturn',
                'dstore','dstore_0','dstore_1','dstore_2','dstore_3','dsub','dup','dup_x1','dup_x2',
                'dup2','dup2_x1','dup2_x2','f2d','f2i','f2l','fadd','faload','fastore','fcmpg',
                'fcmpl','fconst_0','fconst_1','fconst_2','fdiv','fload','fload_0','fload_1',
                'fload_2','fload_3','fmul','fneg','frem','freturn','fstore','fstore_0',
                'fstore_1','fstore_2','fstore_3','fsub','getfield','getstatic','goto','goto_w',
                'i2b','i2c','i2d','i2f','i2l','i2s','iadd','iaload','iand','iastore','iconst_m1',
                'iconst_0','iconst_1','iconst_2','iconst_3','iconst_4','iconst_5','idiv',
                'if_acmpeq','if_acmpne','if_icmpeq','if_icmpge','if_icmpgt','if_icmple',
                'if_icmplt','if_icmpne','ifeq','ifge','ifgt','ifle','iflt','ifne','ifnonnull',
                'ifnull','iinc','iload','iload_0','iload_1','iload_2','iload_3','impdep1',
                'impdep2','imul','ineg','instanceof','invokedynamic','invokeinterface',
                'invokespecial','invokestatic','invokevirtual','ior','irem','ireturn','ishl',
                'ishr','istore','istore_0','istore_1','istore_2','istore_3','isub','iushr',
                'ixor','jsr','jsr_w','l2d','l2f','l2i','ladd','laload','land','lastore','lcmp',
                'lconst_0','lconst_1','ldc','ldc_w','ldc2_w','ldiv','lload','lload_0','lload_1',
                'lload_2','lload_3','lmul','lneg','lookupswitch','lor','lrem','lreturn','lshl',
                'lshr','lstore','lstore_0','lstore_1','lstore_2','lstore_3','lsub','lushr',
                'lxor','monitorenter','monitorexit','multianewarray','new','newarray',
                'nop','pop','pop2','putfield','putstatic','ret','return','saload','sastore',
                'sipush','swap','tableswitch','wide']


def count_asm_registers(asm_code):
    registers_values = [0]*len(registers)
    for row in asm_code:
        parts = row.replace(',',' ').replace('+',' ').replace('*',' ').replace('[',' ').replace(']',' ') \
                    .replace('-',' ').split()
        for register in registers:
            registers_values[registers.index(register)] += parts.count(register)
    return registers_values


def count_asm_opcodes(asm_code):
    opcodes_values = [0]*len(opcodes)
    for row in asm_code:
        parts = row.split()

        for opcode in opcodes:
            if opcode in parts:
                opcodes_values[opcodes.index(opcode)] += 1
                break
    return opcodes_values
    
    
def extract_asm_features(tfiles, feature_file, api_file):
    
    pid = os.getpid()
    print('Process id:', pid)
    feature_file = 'data/' + str(pid) + feature_file # libc API, symbols, registers, opcodes, etc...   
    print('feature file:', feature_file)

    fapi = open("data/elf-libc-api.txt")
    defined_apis = fapi.readlines()
    for idx, fname in defined_apis:
        defined_apis[idx] = fname.rstrip() # Remove newlines, they are annoying.

    asm_files = [i for i in tfiles if '.asm' in i]
    ftot = len(asm_files)
    
    feature_counts = []
    with open(feature_file, 'w') as f:
        # write the csv header
        fw = writer(f)
        colnames = ['file_name'] + registers + opcodes + defined_apis + keywords
        fw.writerow(colnames)
        
        for idx, fname in enumerate(asm_files):
            fasm = open(ext_drive + fname, 'r')
            content = fasm.readlines()
            
            reg_vals = count_asm_registers(content)
            opc_vals = count_asm_opcodes(content)
            api_vals = count_asm_APIs(content, defined_apis)
            sec_vals = count_asm_sections(content)
            mis_vals = count_asm_misc(content)
            count_vals = reg_vals + opc_vals + api_vals + mis_vals + sec_vals
            
            feature_counts.append([fname[:fname.find('.asm')]] + count_vals)   
            
            # Writing rows after every 10 files processed
            if (idx+1) % 10 == 0:
                print("{:d} Processed {:d} of {:d} total files.".format(pid, idx + 1, ftot))
                fw.writerows(feature_counts)
                feature_counts = []
                
        # Writing remaining files
        if len(feature_counts) > 0:
            fw.writerows(feature_counts)
            feature_counts = []

    return


# Start of Script

ext_drive = '/opt/vs/train1/'
tfiles = os.listdir(ext_drive)
print("Total Files: {:d}".format(len(tfiles)))

extract_asm_features(tfiles)

# End of Script
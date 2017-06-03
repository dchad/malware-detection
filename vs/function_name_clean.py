# function_name_clean.py


def sort_function_names()
    # Need to clean up and sort these function names for ASM feature extraction.
    fip = open('data/all-function-column-names-multiline.csv')
    function_names = fip.readlines()
    fip.close()

    function_names.sort()
    function_names[:50]

    fop = open('data/sorted-function-names-multiline.txt','w')
    fop.writelines(function_names)
    fop.close()
    
    return


def combine_name_and_api()
    # Combine the sorted function names and API list.
    fip = open('data/sorted-function-names-multiline.txt','r')
    sorted_function_names = fip.readlines()
    fip.close()
    fip = open('data/APIs.txt','r')
    api_names_str = fip.readline()
    fip.close()
    api_names_str = api_names_str.rstrip()
    api_names = api_names_str.split(',')
    api_names.sort()
    len(api_names)

    for idx in range(len(sorted_function_names)):
        sorted_function_names[idx] = sorted_function_names[idx].rstrip()

    for aname in api_names:
        if aname not in sorted_function_names:
            sorted_function_names.append(aname)

    sorted_function_names.sort()
    #len(sorted_function_names)
    
    return sorted_function_names


def calculate_average_name_length()
    function_count = len(sorted_function_names)
    total_chars = 0
    for func_name in sorted_function_names:
        total_chars += len(func_name)

    avg_name_len = int(total_chars / function_count)

    return avg_name_len


def truncate_function_names(sorted_function_names):
    # truncate function names to reduce the size of the huge sparse matrix.
    function_column_names = []
    for func in sorted_function_names:
        if func.startswith('sub') or func.startswith('loc') or func.startswith('unk'):
            func = func[:5] # lets try to reduce the vast number of functions.
        elif func.startswith('eax+') or func.startswith('ebx+') or func.startswith('ecx+') or func.startswith('edx+'):
            func = func[:3]
        elif func.startswith('edi+') or func.startswith('esi+'):
            func = func[:3]
        elif func.startswith('byte_') or func.startswith('word_') or func.startswith('off_'):
            func = func[:4]
        elif func.startswith('_') or func.startswith('$'):
            func = func[1:]
        elif func.startswith('__') or func.startswith('$$'):
            func = func[2:]
        #else: need a regex here to match a bunch of random crap 
        #    func = func[:33]

        if len(func) > 32: # Reduce the the function name length to max of average function length.
            func = func[:32]

        if func not in function_column_names:    
            function_column_names.append(func)
        
    return function_column_names


def save_reduced_function_names(function_column_names)
    fop = open('data/sorted-reduced-function-names.txt','w')

    for fname in function_column_names:
        fop.write(fname + "\n")

    fop.close()
    
    return


def remove_hex_addresses():
    # Use a regex to remove function names that are just hexadecimal addresses.
    p1 = re.compile('\d\w+h')
    reduced_function_names = []
    fip = open('data/sorted-reduced-function-names.txt','r')
    function_column_names = fip.readlines()
    fip.close()

    fop = open('data/sorted-reduced-function-names-hexless.txt','w')
    for fname in function_column_names:
        fname = fname.rstrip()
        m = p1.match(fname)
        if m == None:
            fop.write(fname + "\n")
            reduced_function_names.append(fname)

    fop.close()
    reduced_function_names[:50]
    
    return





# Start of Script
if __name__ == "__main__":

    # TODO: add command line arguments to specify file names.

    sort_function_names()
    sorted_function_names = combine_name_and_api()
    function_column_names = truncate_function_names(sorted_function_names)
    save_reduced_function_names(function_column_names)

    # Optional
    # remove_hex_addresses()

# End of Script

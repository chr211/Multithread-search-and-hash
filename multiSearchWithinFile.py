'''
Cybv 312 final project module containing helper function for 
multisearchandhash module
This function searces within one file for value (string).
It searches by chunksize by chunksize. Also, at the end
of each iteration, it searches across the borders of chunks.

'''

''' IMPORT STANDARD LIBRARIES '''
import os       # File System Methods
import time     # Time Conversion Methods
import sys
import hashlib
import re
from binascii import hexlify 
import errno

def searchWithinFile(value, entry):
    '''
    search for value within a given file path entry
    entry[0] contains the file path
    '''
    
    bytesProcessed = 0#set to 0 for each new file
    try:
        with open(entry[0], 'rb') as contents:
            #read in chunks
            print(f"\nSearching {entry[0]} for {value} ", end = '')
            
            while True:#keep reading the file by chunks until chunk is empty, then break
                fileSize = os.path.getsize(entry[0])
                chunkSize = int(fileSize / 10)#size of waiting progress dot and chunkSize
                if chunkSize == 0:
                    chunkSize == 1#if it's a small file and I got a float from division 
                    
                fileChunk = contents.read(chunkSize)#read chunkSize from file
                bytesProcessed += len(fileChunk)#keep track of processed bytes for future use
                if fileChunk:#if non empty
                    hexDump = hexlify(fileChunk)#get 
                    #print(hexDump.decode("utf-8")) Debug

                    #Use utf-8 for now. Try out with other encodings later 
                    #Find the search value encoded in utf-8 within this hex chunk
                    lookResult = hexDump.find(hexlify(bytes(value, 'utf-8')))
                    if lookResult != -1: #-1 means not found, otherwise index value is returned
                        print(f"\nFound term \'{value}\' in {entry[0]}")#stop searching - return filepath to found file
                        return entry
                        
                    else:
                        #the word may be the boarder - merge current chunk with next chunk and search again
                        #remember chunk position
                        chunkStart = contents.tell()#tell shows the current file pointer location
                        fileChunk = contents.read()#get next chunk
                        if fileChunk:#if not done with file
                            nextHexDump = hexlify(fileChunk)#get hex value
                            #combine current and len(value)*2 bytes of next hex dump and search for byte string
                            comboDump = hexDump+nextHexDump[0:len(value)*2]
                            lookResult = comboDump.find(hexlify(bytes(value, 'utf-8')))#search the combination of current and next chunk
                            
                            if lookResult != -1: #if found, return file path
                                print(f"\nFound term \'{value}\' in {entry[0]}")
                                return entry
                                
                                
                            else:#rewind the file pointer for start of next iteration
                                contents.seek(chunkStart)
                                
                        else:#no more chunks during border search, break main while loop. This is for debugging and moving the curser to erase line
                            #print('\r')
                            break#no more chunks
                        
                    print(".", end = '')#progress dots to show something is actually happening                            
                
                else:#no more chunks during standard non-border search, break while loop
                    #print('', end = '\r')#erase search term
                    break#no more chunks
                                        
    except Exception as err:
        print("Error in chunker: " + str(err))
            
    
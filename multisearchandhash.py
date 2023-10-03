'''
Script:  Final project cybv 312
Author:  Christopher O'Brien
Date:    October 10 2020
Version: 1.2 *multiprocessor search within file version
Purpose: 
Jump to line 274 to see relevant code.
I modified the homework #4 file search capability to search for text within a string using
multiprocessing. It uses cpu_count() to create a new process for file search target.
This let's the program search within several files in a true parallel fashion sigificantly 
speeding up the overall search. This is useful for forensic applications in cases were the file
system is large and the decrease in search time can speed up investigations.  Note that the search function 'searchWithinFile itself
is in another module called multiSearchWithinFile. 

Version 1.2 fixed a bug within searchWithinFile that did not correctly search border cases.

Prompt user for start directory and list contents of all subdirectories using os.walk. 
For each entry list the full path, file size, MAC times in UTC, and SHA256 hash for files.
The table is sorted by file size.
Search for a file by: exact name, extension, hash value, or string within file.
Change directory during runtime.(Deletes previous hash values)
Option 5 or 3 must be chosen first to see a hash value within any search result.
Adapted from FirstScript.py and WalkFileSystem.py by Chet Hosmer
'''

''' IMPORT STANDARD LIBRARIES '''
import os       # File System Methods
import time     # Time Conversion Methods
import sys
import hashlib
import re
from binascii import hexlify 
import errno
import multiprocessing
import multiSearchWithinFile
from functools import partial

''' IMPORT 3RD PARTY LIBRARIES '''
# Format the output table so it looks nice
from prettytable import PrettyTable #pip install prettytable

''' DEFINE PSEUDO CONSTANTS '''
#NONE
CHUNK_SIZE = 1024

''' LOCAL FUNCTIONS '''
def GetDirectoryTreeContents():
    '''
    prompt user for directory and retrieve the contents. 
    Store the contents of the sub directory tree in a list structure and return.
    return success=True, error , pathList, and full root path
    '''
    
    try:
        # prompt user for directory
        directoryPath = input("Enter Directory Path i.e. c:/ >>>: ")
        print("\nUser Entered Directory: ", directoryPath)
    
        if not os.path.isdir(directoryPath):
            print("Directory not found.")
            raise Exception('Directory not found.')        
        
            
        pathList = []#store all the entries with full path
        for root, dirs, files in os.walk(directoryPath):
            
            for entry in files:
                
                pathList.append(os.path.abspath(os.path.join(root, entry)))#add entry to list
        
        return True, None, pathList, os.path.abspath(directoryPath)  #No Errors, return a list with paths to all paths in sub directories
    except Exception as err:
        return False, str(err), None, None
    
def GetFileMetaData(fileName):
    ''' 
        obtain file metadata
        from the specified file
        specifically, fileSize and MAC Times
        This function calculates the epoch time.
        return True, None, fileSize and MacTimeList
    '''
    try:
        
        metaData         = os.stat(fileName)       # Use the stat method to obtain meta data
        fileSize         = metaData.st_size         # Extract fileSize and MAC Times
        timeLastAccess   = metaData.st_atime
        timeLastModified = metaData.st_mtime
        timeCreated      = metaData.st_ctime
        
        macTimeList = [timeLastModified, timeLastAccess, timeCreated] # Group the MAC Times in a List
        return True, None, fileSize, macTimeList
    
    except Exception as err:
        return False, str(err), None, None

def PrintContents(contents):
    '''
    Print the contents of the directory using a left justified prettytable.
    The columsn are fullPath, filesize, Modified time, Accessed time, Created time, SHA256 Hash.
    This should only be called after hashfiles(), otherwise no hash value will exist and an exception will occur.
    Return True if okay, else return False and exception
    '''
    try:
        print("Printing results")
        table = PrettyTable()
        
        
        if(len(contents)==0):
            raise Exception("No contents to print!")
        
        if len(contents[0])==4:#Check entry for hash value
            table.field_names = ["File Name", "File Size", "Modified", "Accessed", "Created", "SHA256 Hash"]
        else:
            table.field_names = ["File Name", "File Size", "Modified", "Accessed", "Created"]
        #wrap long file paths
        table._max_width = {'File Name' : 100}
        
        #convert the epoch times to UTC on the fly rather than permanently modifying them
        #entry[3] has the hash value
        for entry in contents: #MAC times are in a list at position entry[2] and in a sub-list of size 3
            
            modifiedUTC = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(entry[2][0]))
            accessedUTC = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(entry[2][1]))
            createdUTC = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(entry[2][2]))
            if len(entry)==4: 
                table.add_row([entry[0], entry[1], modifiedUTC, accessedUTC, createdUTC,entry[3]])#entry 0 and 1 are File Name and Size
            else:
                table.add_row([entry[0], entry[1], modifiedUTC, accessedUTC, createdUTC])#There's no hash to add in this case
        table.align = "l"
    
        resultString = table.get_string(sortby="File Size")#sort by file size
        print(resultString)#print out the pretty table stored in string form
    
        return True, None
    
    except Exception as err:
        print("Error in printing pretty table: " + str(err))
        return False, str(err)

def HashFiles(fileList):
    '''
    fileList is a list containing file entries. 
    Each entry is also a list with the first index being the
    full path of the file to hash.
    It returns a new list identical to fileList with an additional 
    index for each entry that contains the hash value.
    ***This must only be called after GetFileMetaData because after the hash value is added
    subsequent calls to GetFileMetaData will overwrite it.
    '''

    try:
        print(f"Please wait...")
        
        hashListSize = len(fileList)
        cnt = 0; #current entry number
        #These are for the progress display
        left = '\\'
        right = '/'
        direction = left        
        
        outList = []#outputList to copy old list to plus hash entry.
        newEntry = []# a new entry list with the hash value at the end
        for entry in fileList:
            newEntry = [] # updated entry with hash value
            try:
                with open(entry[0], 'rb') as target:
            
    
                    #get the raw binary(don't interpret) contents of each directory entry
                    fileContents = target.read()
                
                    sha256Obj = hashlib.sha256()#create a sha256 hash object to store file info 
                    sha256Obj.update(fileContents)#store the file info in the hash object
                    hexDigest = sha256Obj.hexdigest()#generate sha256 hash using filecontents
                    
                    #There is no pre existing hashlist, just append hashes to metadata list and return new list
                    #copy old data (path, size, MAC) over to new entry and then add hash to the end
                    for meta in entry:
                        newEntry.append(meta)
                    #add hash
                    newEntry.append(hexDigest)
                    #add entry to outputList
                    outList.append(newEntry)
                    
                    #print progress every 1%
                    progress = int(100*cnt/len(fileList))
                    
                    #This show a little animation for progress during large hashing jobs
                    print("Hashing " + f"{progress}" + "%" + direction, end = '\r')
                    cnt += 1
                    if(direction == left):
                        direction = right
                    else:
                        direction = left
                #debug print("\n\n",entry[0], " SHA-256 Hex Digest = ", hexDigest, "\n\n")
                #This is my very ugly way of dealing with no read access and skipping this file            
            except IOError as err:
                if err.errno == errno.EACCES:
                    print(f"Error reading file {entry[0]}")
                    #move on the next entry                
        
        print()#newline after progress
           
        return True, None, outList #return the update entry list
    except Exception as err:
        print("Error in hashing. Exiting")
        sys.exit()
    
    
def FindFile(EntryList, mode, value):
    '''
    Find a file by fileName or SHA 256 Hash value
    EntryList -- is the list of entries. Each entry is a list 
    Format of Entrylist is: entry[0] has the full file path.
    Split returns a tuple where [1] is the filename in the full
    path. Entry[2] is the time meta in a list of size 3.
    entry[3] is where the hashvalue is stored
    Mode -- 1 search for file containing entire string in value
    Mode -- 2 search for file by extension. Dot must be ommitted in call.
    Mode -- 3 search for file by hash value.
    Mode -- 4 search for file containing complete string in value. v1.2 now searches across 2 chunks
    TODO count occurences of text in file
    '''
    foundFileList = []#list of all paths where file was found
    try:#Big switch statement with 5 search mode choices
        if mode == 1:#search by full file name
            for entry in EntryList:
                if os.path.split(entry[0])[1].lower().find(value.lower()) >= 0:#compare full filename including extension
                    if(len(value) == len(os.path.split(entry[0])[1])):#length must match - no substrings!
                        if os.path.isfile(entry[0]):#check if its a standard file
                            foundFileList.append(entry)
                            print(f"Found {value} at {entry[0]}")
                        else:
                            print("Not a file")#shouldn't happen
            
        elif mode == 2:#search for file type
            if value[0] == '.':#they included a leading '.'
                pat = re.compile(f'.\.{value[1:]}$', re.IGNORECASE)
            else:
                pat = re.compile(f'.\.{value}$', re.IGNORECASE)# search for file extension at end of string only ignore case
            
            print(f"Search files with extention {value} ")
            
            for entry in EntryList:
                ext = pat.search(os.path.split(entry[0])[1])#extract the file name from tuple
                if ext != None:
                    print(f"Found file with extension {value} in {entry[0]} ")
                    foundFileList.append(entry)
                
        elif mode == 3:#search for hash value in entry[3]
            print("Searching for hash value")
            
            for entry in EntryList:
                if entry[3] == value:
                    #print(f"Found {value} at {entry[0]}")
                    foundFileList.append(entry)
                    
            if len(foundFileList) == 0:
                print(f"{value} not found.")
            else:
                print("Total Hash Matches:")
                #debugging for found in foundFileList: 
                    #print(f"Found {value} at {found[0]}")
                    
        elif mode == 4:#search for string within a file
            if len(value) == 0:#search string is empty
                print("Search string is empty.")
                raise Exception('Search string is empty.') 
            print("Searching for data within a file.")
            
            #Go through directory list and search each file for value
            #set the number of parallel processes to the number of cores
            corePool = multiprocessing.Pool(multiprocessing.cpu_count())
            #map only takes 1 argument, so since the search value does not change, create a partial function and pass that instead 
            fun = partial(multiSearchWithinFile.searchWithinFile,value)#partial function with value always the same 
            
            resultList = corePool.map(fun,EntryList)#search the iterable entryList for value  
            #remove 'None' return values that were returned for when the value was not found in a file
            #this is an ugly way of doing this, but it works
            for f in resultList:
                if f != None:
                    foundFileList.append(f) #return these files which contain the search string
            #close pool and wait
            corePool.close()
            corePool.join()
        else:
            print("invalid mode")
            return False, None, "Invalid Mode"
            
        if len(foundFileList):
            return True, foundFileList, None
        else:
            return False, None, None
                        
    except Exception as err:
        print("Error in find: " +str(err))
        return None, None, err
''' LOCAL CLASSES '''
# NONE

''' MAIN ENTRY POINT '''
#running directly 
if __name__ == '__main__':
    metadataOutputList = [] #Each list item is a list that holds the path, fileSize, and MAC times for a directory entry
    
    print("\nHW3 Solution: Christopher O'Brien - Version One\n")
    
    success, errInfo, dirContentNames, root = GetDirectoryTreeContents()# get a list of all the directory entry full paths
    if not success:
        print('No root set')
    else:    
        for entry in dirContentNames:# get metadata for each directory entry 
            success, errInfo, fileSize, macList = GetFileMetaData(entry)#get corresponding metadata for each entry
            if success:
                metadataOutputList.append([entry,fileSize,macList])#entry name and corresponding metadata
            else:
                print("Failure in metadata retrieval:    ", entry, "Exception =     ", errInfo)
        
    
        
    choice = {0,1,2,3,4,5,6,7,8}#menu choices
    hashList = []#This is the metadataOutputList with hash values appended
    hashListExists = False#on startup no hashlist exists. Only hash files if searching by hash or if calculate hashes is selected
    while True:
        print()
        print("1. Find a file by name (Case insensitive).")
        print("2. Find all files by type.")
        print("3. Find file by hash value.")
        print("4. Find file containing text string.")
        print("5. Calculate hashes for current selected directory tree.")
        print("6. Change root directory to search from.")
        print("7. Print current tree contents.")
        print("8. Print current tree root.")
        print("0. Exit program.")
        mode = input()
        try:
            int(mode)
        except Exception:
            print("Enter a valid number.")
            continue#User enter non integer, ask again
            
        #User-entered mode must be in choice list, 1-5
        if choice.__contains__(int(mode)):
            if int(mode) == 0:#Exit and don't waste any more time
                print('Goodbye.')
                sys.exit()
            
            
            
            if int(mode) == 3:#Search by hash needs to call HashFiles first
                print("Enter hash value: ")
                value = input()                    
                if hashListExists == False:#on first search if a hash list doesn't exists, make one
                    print("Creating new hash list first. Please wait...")
                    success, errInfo , hashList = HashFiles(metadataOutputList)#create new list
                    
                    if success:
                        success, foundList, err = FindFile(hashList,int(mode), value)
                        hashListExists = True
                        if success:
                            print("Found Files.")
                            for found in foundList:
                                PrintContents(foundList)
                        else:
                            print("Hash not found")
                    else:
                        print("Problem creating hash file database")
                else:#hashList already exists, use it to search
                    success, foundList, err = FindFile(hashList,int(mode), value)#FindFile uses mode value to choose how to search
                    if success:
                        
                        PrintContents(foundList)
                    else:
                        print("Hash not found")
                        
            elif int(mode) == 5:#calculate hashes for file tree
                if hashListExists:#if a previous hashlist exists, overwrite existing hashList with new one
                    success, errInfo , hashList = HashFiles(metadataOutputList)
                    if success:
                        hashListExists = True
                        print("Success! hashlist created.")
                    else:
                        print("Problem creating hash file database")
                else:
                    success, errInfo, hashList = HashFiles(metadataOutputList)
                    if success:
                        print("Success! hashlist created.")
                        hashListExists = True
                    else:
                        print("Problem creating hash file database.")

            elif int(mode) == 6:#Change root dir. Reload metadataOutputList from new root directory
                success, errInfo, dirContentNames, newRoot = GetDirectoryTreeContents()# get a list of all the directory entry full paths
                #newRoot is None if invalid input, so don't change root variable 
                if success:
                    metadataOutputList = [] #Reset the list to emtpy.Each list item is a list that holds the path, fileSize, and MAC times for a directory entry
                    hashList = []# reset HashList so it doesn't remember old directory values 
                    hashListExists = False
                    root = newRoot
                    
                    for entry in dirContentNames:# get metadata for each directory entry 
                        success, errInfo, fileSize, macList = GetFileMetaData(entry)#get corresponding metadata for each entry
                        if success:
                            metadataOutputList.append([entry,fileSize,macList])#entry name and corresponding metadata
                        else:
                            print("Failure in metadata retrieval:    ", entry, "Exception =     ", errInfo)
                else:
                    print('Error retrieving directory.')
                    print(f'Current directory is: {root}')
                    
            elif int(mode) == 7:#print current directory listing. user needs to select choice 5 first for hashes to show
                if len(hashList)>0:#don't print out empty list
                    PrintContents(hashList)
                else:
                    PrintContents(metadataOutputList)
                    
            elif int(mode) == 8:
                print(f"Current root of tree: {root}")
                
            else:#choices #1,2,4 have no need to spend time calculating hashes, unless previously requested by choice 5
                print("Enter search term: ")
                value = input()
                
                startTime = time.time()
                
                if len(hashList)>0:#search hashList if it exists
                    success, foundList, err = FindFile(hashList,int(mode), value)
                else:
                    success, foundList, err = FindFile(metadataOutputList,int(mode), value)
                    
                if success:
                    print(f"Found {len(foundList)} files.")
                    PrintContents(foundList)
                else:
                    print(f"No files found.")
                    
                endTime = time.time()
                print(f'Time taken: {endTime - startTime} seconds.')                
            #break out of the option choice if valid choice
        else:
            print("Invalid choice Try again.\n")

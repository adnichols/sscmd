#!/usr/bin/env python -W all

import httplib2, urllib2, sys, re, time, os, string
from xml.dom import minidom
from optparse import OptionParser
from stat import *

total_time = []
h = httplib2.Http(cache=".cache", timeout=5)

# Command line options
parser = OptionParser()
parser.add_option("--debug", action="store_true", help="Enable debugging")
parser.add_option("--verbose", action="store_true", help="Enable verbose output")
parser.add_option("--list", action="store_true", help="List items")
parser.add_option("--authfile", help="Authentication file to use", default="auth.xml")
parser.add_option("--api_url", help="API URL to use", default="https://api.sugarsync.com")
parser.add_option("--workspace", help="Workspace to use")
parser.add_option("--folder", help="Folder to use")
parser.add_option("--upload", help="Upload this file to service")
parser.add_option("--type", help="Specify the mime type of file for upload")
parser.add_option("--time", action="store_true", help="Time operations")
parser.add_option("--listws", action="store_true", help="List available workspaces")
parser.add_option("--raw", help="Get a raw URL and display response")
parser.add_option("--rawdl", help="Download file from raw URL")
parser.add_option("--rawparent", help="Parent Folder URL to use for file uploads")
parser.add_option("--delete", help="Delete files matching this name in defined folder")
parser.add_option("--nossl", action="store_true", help="Convert any ssl links to non-ssl links (hack)")

parser.set_defaults(
    debug=False,
    verbose=False,
    authfile="auth.xml",
    api_url="https://api.sugarsync.com"
    )

(options, args) = parser.parse_args()

if (options.debug is True):
    print "D: Debug is enabled"

def GetAuthToken():
    '''Get an authentication token - returns two values, response & token'''
    # Read in auth data
    s = time.time()
    in_file = open(options.authfile, "r")
    authdata = in_file.read()
    T("read_auth_config", s)
    s = time.time()
    resp, content = h.request(options.api_url + "/authorization", "POST", authdata,
                              headers={'Content-type':'application/xml; charset=UTF-8', 'cache-control': 'no-cache'})
    token = resp["location"]
    response = resp["status"]
    return(response, token)
    
def D(data_input):
    '''Prints data_input to stderr for debugging'''
    if (options.debug is True):
         sys.stderr.write("D: %s\n"%data_input)

def V(data_input):
    '''Prints data_input to stdout for verbosity'''
    if (options.verbose is True):
         sys.stdout.write(data_input)
    
def T(op, stime):
    '''Print result of timing operation'''
    if (options.time is True):
        t = (time.time() - stime)
        sys.stderr.write("T: {0} : {1:.3}\n".format(op, t))
        total_time.append(t)
    
def getText(nodelist):
    '''Turns XML data into text'''
    rc = []
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc.append(node.data)
    return ''.join(rc)
    
def GetXmlUrl(url):
    '''Gets a URL and returns an xml object of the response'''
    D("Getting URL: " + url)
    
    # Check to see if we already have the hostname in the URL
    if not re.match("http", url):
        url_req = (options.api_url + url)
    else:
        url_req = url
    s = time.time()
    resp, content = h.request(url_req, "GET", headers={'Authorization': token})
    T("get_xml_url: " + url, s)
    return(minidom.parseString(content))
    
def PostXmlToUrl(url, xml):
    '''POST xml to a url and return resulting xml response'''
    D("Posting to URL: " + url)
    
    # Check to see if we already have the hostname in the URL
    if not re.match("http", url):
        url_req = (options.api_url + url)
    else:
        url_req = url
    headers = {'Authorization': token,
               'Content-type': "application/xml; charset=UTF-8"}
    s = time.time()
    resp, content = h.request(url_req, "POST", xml, headers=headers)
    T("post_xml_url: " + url, s)
    return(content)
    
def GetUserInfo(field):
    '''Gets the specified field from the userinfo for the current user'''
    userinfo = GetXmlUrl("/user")
    return getText(userinfo.getElementsByTagName(field)[0].childNodes)
    
def GetWorkspaceList():
    '''Gets a list of workspaces for the curren user'''
    namelist = []
    ws_url = GetUserInfo("workspaces")
    ws_xml = GetXmlUrl(ws_url)
    for collection in ws_xml.firstChild.childNodes:
        colname = getText(collection.getElementsByTagName("displayName")[0].childNodes)
        colref = getText(collection.getElementsByTagName("ref")[0].childNodes)
        coliconid = getText(collection.getElementsByTagName("iconId")[0].childNodes)
        colcontents = getText(collection.getElementsByTagName("contents")[0].childNodes)
        namelist.append(colname)
    return namelist

def GetWorkspaceInfo(name, node):
    '''Gets a reference for a given workspace name'''
    s = time.time()
    D("Fetching name: " + name + "\n")
    D("Fetching node: " + node + "\n")
    ws_url = GetUserInfo("workspaces")
    ws_xml = GetXmlUrl(ws_url)
    for collection in ws_xml.firstChild.childNodes:
        colname = getText(collection.getElementsByTagName("displayName")[0].childNodes)
        colnode = getText(collection.getElementsByTagName(node)[0].childNodes)
        D("Processing Workspace" + colname)
        if (colname == name):
            D("Matched workspace:" + colname)
            D("Returning Node: " + colnode)
            T("GetWorkspaceInfo", s)
            return colnode

def ListAllWorkspace():
    '''Displays all workspaces for current user'''
    wslist = GetWorkspaceList()
    print "Workspace List:"
    for space in wslist:
        print space

def GetRawUrl(url):
    '''Used for debugging - pass a URL and it fetches raw xml'''
    s = time.time()
    xml = GetXmlUrl(url)
    T("GetRawUrl: ", s)
    print xml.toprettyxml()
        
def GetFile(url):
    '''Used for testing, get a file from a specific URL'''
    if not re.match("http", url):
        url_req = (options.api_url + url)
    else:
        url_req = (url)
    headers = {'Authorization': token}
    
    try:
        total_size = 0
        s = time.time()
        f = h.request(url_req, "GET", headers=headers)
        data_list = []
        chunk=1024000
        local_file = open("/var/tmp/testdl", "w")
        while True:
            data = f.read(chunk)
            if not data:
                print 'done'
                break
            total_size+=len(data)
            data_list.append(data)
            local_file.write(data)
            sys.stdout.write('+',)
            sys.stdout.flush()
        
        t = (time.time() - s)
        T("file_rawdl", s)
        kbps = (((total_size / t) * 8) / 1024)
        if (options.time):
            print("kbits/sec: %5.3f"%kbps)
        # Open a local file
        local_file.close()
        
    except httplib2.HTTPLib2Error, e:
        print "HTTP Error:", e.code, url_req
    
def GetFileRefByName(folder, name):
    '''Returns a file ref based on a file name & folder by searching contents of folder'''
    filename_absolute = os.path.abspath(name)
    filename = os.path.basename(filename_absolute)
    folder_contents = GetXmlUrl(folder + "/contents?type=file")
    for fileinfo in folder_contents.firstChild.childNodes:
        file_name = getText(fileinfo.getElementsByTagName("displayName")[0].childNodes)
        file_ref = getText(fileinfo.getElementsByTagName("ref")[0].childNodes)
	if (options.nossl):
	    ref = string.replace(file_ref, "https://", "http://")
	else:
	    ref = file_ref
        if (file_name == filename):
            D("Found ref for file: " + name + " : " + ref + "\n")
            return ref
#   except:
#       sys.stderr.write("Error: file '%s' not found in folder '%s'\n"%(name, folder))
#       sys.exit()
    
def CreateFile(folder):
    '''Performs POST to create a new empty file'''
    filename_absolute = os.path.abspath(options.upload)
    filename = os.path.basename(filename_absolute)
    mode = os.stat(filename_absolute)[ST_MODE]
    size = os.stat(filename_absolute)[ST_SIZE]
    type = options.type
    if S_ISREG(mode):
        print("File: %s :: Size: %d bytes\n"%(filename_absolute,size))
    else:
        print("'%s' is not a regular file & cannot be uploaded"%filename)
        sys.exit()
        
    xml = '<?xml version="1.0" encoding="UTF-8"?><file><displayName>' + filename + '</displayName><mediaType>' + type + '</mediaType></file>'
    D("XML: " + xml)
    post_resp = PostXmlToUrl(folder, xml)
    
def UploadFileData(file_url):
    '''Performs upload of file data'''
    local_file = open(options.upload, "r")
    filename_absolute = os.path.abspath(options.upload)
    filename = os.path.basename(filename_absolute)
    mode = os.stat(filename_absolute)[ST_MODE]
    size = os.stat(filename_absolute)[ST_SIZE]
    headers = {'Authorization': token, 'Content-type': options.type}
    s = time.time()
    resp, content = h.request(file_url + "/data", "PUT", local_file.read(), headers=headers)
    T("upload_file_data: ", s)
    ul_time = (time.time() - s)
    kbps = (((size / ul_time) * 8) / 1024)
    if (options.time):
        print("kbits/sec: %5.3f"%kbps)
    local_file.close()
    
    
def DeleteFile(file_url):
    '''Deletes the file specified by ref (url)'''
    headers = {'Authorization': token}
    s = time.time()
    resp, content = h.request(file_url, "DELETE", headers=headers)
    T("delete_file: ", s)
    
def DeleteFilesByName():
    '''Deletes all files matching the specified name in a folder'''
    filename_absolute = os.path.abspath(options.delete)
    filename = os.path.basename(filename_absolute)
    deleted_files = []
    folder_contents = GetXmlUrl(options.folder + "/contents?type=file")
    for fileinfo in folder_contents.firstChild.childNodes:
        file_name = getText(fileinfo.getElementsByTagName("displayName")[0].childNodes)
        file_ref = getText(fileinfo.getElementsByTagName("ref")[0].childNodes)
	if (options.nossl):
	    ref = string.replace(file_ref, "https://", "http://")
	else:
	    ref = file_ref
        if (file_name == filename):
            D("Deleting file: " + filename + " : " + ref + "\n")
            DeleteFile(ref)
            deleted_files.append(filename + ":" + ref)
    return deleted_files
    
# Get an auth token to start
response, token = GetAuthToken()

if (options.listws):
    ListAllWorkspace()

elif ((options.list is True) & (options.workspace is not None)):
    ws_info = GetXmlUrl(GetWorkspaceInfo(options.workspace, "contents"))
    print ws_info.toprettyxml()
    
elif (options.raw is not None):
    GetRawUrl(options.raw)
    
elif (options.rawdl is not None):
    GetFile(options.rawdl)
    
elif ((options.upload is not None) & (options.folder is not None)):
    resp = CreateFile(options.folder)
    file_ref = GetFileRefByName(options.folder, options.upload)
    ul_resp = UploadFileData(file_ref)
    
elif ((options.delete is not None) & (options.folder is not None)):
    deleted_files = DeleteFilesByName()
    
if (options.time):
    tt = 0
    for t in total_time:
        tt+=t
    print("Total Time: %5.3f secs"%tt)


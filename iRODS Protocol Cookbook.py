#!/usr/bin/env python
# coding: utf-8

# # IRODS Protocol Cookbook
# 
# This notebook will provide example implementations of key 
# operations in the iRODS protocol. Read from the beginnging or use this table of contents to skip to the section that interests you. Once you've jumped to that spot, make sure the cell with the anchor is selected and run `Cell > Run All Above`.
# 
# ## Table of Contents
# 
# * [Handshake](#handshake)
# * [Authentication](#authentication)
# * [ils](#ils)
#     - [Stat a collection](#stat_coll)

# In[2]:


## We'll be doing this from scratch, so all imports will come from 
## the Python standard library or 3rd-party tools
import socket
import struct
import base64
import json
import hashlib
import time
import enum
import xml.etree.ElementTree as ET
from enum import Enum

import pandas as pd


# This tutorial assumes you have deployed iRODS in Docker using
# the script stand_it_up.py from the iRODS Testing Environment, 
# which can be found on Github [here](https://github.com/irods/irods_testing_environment)
# To find the IP address associated with your Docker container, you can run this one-liner:
# ```bash
# docker inspect   -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ubuntu-2004-postgres-1012_irods-catalog-provider_1
# ```
# Otherwise, if want to try this out on a real-world zone, insert that zone's hostname here.

# In[ ]:


HOST = "172.28.0.3"


# In[4]:


PORT = 1247 ## This is the standard iRODS port
MAX_PASSWORD_LENGTH = 50 ## This constant comes 
                         ## from the internals 
                         ## of the iRODS server
API_TABLE = {
    "AUTHENTICATION_APN":110000, ## The API number for the 4.3.0 auth framework
    "OBJ_STAT_AN":633,
    "GEN_QUERY_AN":702
}

CATALOG_INDEX_TABLE = {
    "COL_COLL_NAME": "501",
    "COL_D_DATA_ID": "401",
    "COL_DATA_NAME": "403"
    "COL_COLL_INHERITANCE": "506"
}


# First, we're going to write a small library of functions that do some 
# of the dirty work. 
# Feel free to skip to [here](#start_of_real_work), where we start using this library to send
# and read messages, referring to this part to figure out how
# the part you're interested in was implemented.

# In[4]:


## We can define these in an enum since 
## header types are a closed class and are not sensitive to any
## particular API.
class HeaderType(Enum):
    RODS_CONNECT = "RODS_CONNECT"
    RODS_DISCONNECT = "RODS_DISCONNECT"
    RODS_API_REQ = "RODS_API_REQ"
    RODS_API_REPLY = "RODS_API_REPLY"
    RODS_VERSION = "RODS_VERSION"

def header(header_type: HeaderType, msg: bytes, 
           error_len=0, bs_len=0, int_info=0) -> bytes:
    return f"""
        <MsgHeader_PI>
            <type>{header_type}</type>
            <msgLen>{len(msg)}</msgLen>
            <errorLen>{error_len}</errorLen>
            <bsLen>{bs_len}</bsLen>
            <intInfo>{int_info}</intInfo>
        </MsgHeader_PI>
        """.replace(' ', '').replace('\n', '').encode('utf-8') ## The protocol is whitespace-insensitive,
                                                               ## but I removed them here for cleanliness
                                                               ## and efficiency for when this gets pushed
                                                               ## through the pipe.


# In[5]:


def send_header(header: bytes, sock: socket) -> None:
    header_len = int.to_bytes(len(header), byteorder='big', length=4) ## The first part of all iRODS messages
                                                                      ## must be 4 bytes indicating how long
                                                                      ## the header is in bytes. These bytes
                                                                      ## and the entire integer must be transmitted
                                                                      ## in big-endian order
    print(header_len)
    sock.sendall(header_len)
    sock.sendall(header)
    
def send_msg(msg: bytes, sock: socket) -> None:
    sock.sendall(msg)
    
def recv(sock: socket) -> [ET, ET]:
    header_len = int.from_bytes(sock.recv(4), byteorder='big')
    print(f"HEADER LEN: [{header_len}]")
    header = sock.recv(header_len).decode("utf-8")
    print(f"HEADER: [{header}]")
    
    msg = sock.recv(
        int(ET.fromstring(header).find("msgLen").text)).decode("utf-8")
    print(f"MSG: [{msg}]")
    
    return ET.fromstring(header), ET.fromstring(msg)


# ## Start of the "Real Work" <a class="anchor" id="start_of_real_work"></a>
# Note that even if you are using a plugin for authentication, iRODS may still refer to the information in the StartupPack_PI during authentication. If you are experiencing bugs during that step, check your Startup Pack as well as the structures associated with your specific plugin.

# In[6]:


class IrodsProt(Enum):
    NATIVE_PROT = 0
    XML_PROT = 1

## Now, let's start the connection process. First, we need an easy way to create the StartupPack.
def startup_pack(irods_prot=IrodsProt.XML_PROT.value,
                 reconn_flag=0, 
                 connect_cnt=0,
                 proxy_user=None,
                 proxy_rcat_zone=None,
                 client_user="rods", 
                 client_rcat_zone="tempZone", 
                 rel_version="4.3.0", 
                 api_version="d", ## This MUST ALWAYS be "d." This value has been hardcoded into iRODS
                                  ## since very early days.
                 option=None ## This option controls, among other things,whether SSL negotiation is required.
                ) -> bytes:
    return f"""
    <StartupPack_PI>
             <irodsProt>{irods_prot}</irodsProt>
             <reconnFlag>{reconn_flag}</reconnFlag>
             <connectCnt>{connect_cnt}</connectCnt>
             <proxyUser>{proxy_user or client_user}</proxyUser>
             <proxyRcatZone>{proxy_rcat_zone or client_rcat_zone}</proxyRcatZone>
             <clientUser>{client_user}</clientUser>
             <clientRcatZone>{client_rcat_zone}</clientRcatZone>
             <relVersion>rods{rel_version}</relVersion>
             <apiVersion>{api_version}</apiVersion>
             <option>{option}</option>
    </StartupPack_PI>
    """.replace(" ", "").replace("\n", "").encode("utf-8")


# We're going to be sending raw bytes over a socket, so let's create one
# If at some point the Notebook stops working, remember
# to manually close the socket.

# In[7]:


conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((HOST, PORT)) 


# ## Handshake <a class="anchor" id="handshake"></a>

# In[8]:


sp = startup_pack()
sp


# In[9]:


h = header(HeaderType.RODS_CONNECT.value, sp)
h


# In[10]:


send_header(h, conn)
send_msg(sp, conn)


# In[11]:


## In this Version_PI, status of 0 lets us know that negotiation has been successful.
h, msg = recv(conn)


# ## Authentication <a class="anchor" id="authentication"></a>
# 
# Next up, we need to authenticate using our API of choice. 
# Since this is a basic cookbook for 4.3.0, we'll be using the new 
# auth framework's port of native authentication.
# This API works by exchanging binary buffers between client and server.
# Since XML must be valid UTF-8, this binary data MUST be base64-encoded.

# In[12]:


def encode_dict_as_base64_json(d: dict): 
    return base64.b64encode(
        json.dumps(d).encode('utf-8'))


# The payload is decoded because otherwise Python will 
# add extra characters to give a string representation of the bytes object

# In[13]:


def read_base64_into_json(bsix: bytes, trunc=False) -> dict:
    decoded = base64.b64decode(bsix).decode('utf-8')
    return json.loads(decoded[:-1]) if trunc else json.loads(decoded)

def bin_bytes_buf(payload: dict) -> bytes:
    payload = encode_dict_as_base64_json(payload)
    return f"""
    <BinBytesBuf_PI>
        <buflen>{len(payload)}</buflen>
        <buf>{payload.decode('utf-8')}</buf>
    </BinBytesBuf_PI>
    """.replace(" ", "").replace("\n","").encode('utf8')


# In[14]:


## Some API-specific parameters
auth_ctx = {
    "a_ttl":"0",
    "force_password_prompt":"true",
    "next_operation":"auth_agent_auth_request",
    "scheme":"native",
    "user_name":"rods",
    "zone_name":"tempZone"
}


# In[15]:


initial_auth_msg = bin_bytes_buf(auth_ctx)
print(initial_auth_msg)
h = header(HeaderType.RODS_API_REQ.value, 
           initial_auth_msg, 
           int_info=API_TABLE["AUTHENTICATION_APN"])
send_header(h, conn)
send_msg(initial_auth_msg, conn)


# In[16]:


h, m = recv(conn)


# If you were writing a real client library or application, you would want to check intInfo for error codes
# so you could respond appropriately. Here, we're going to move on blissfully unaware.

# In[17]:


auth_ctx = read_base64_into_json(m.find("buf").text, trunc=True)
request_result = auth_ctx[ 'request_result']
print(f"REQUEST RESULT: [{request_result}]")


# In[18]:


def pad_password(pw: str) -> bytes:
    return struct.pack("%ds" % MAX_PASSWORD_LENGTH, pw.encode("utf-8").strip())

## Native auth specific operations
m = hashlib.md5()
m.update(request_result.encode("utf-8"))
m.update(pad_password("rods"))
digest = m.digest()
encoded_digest = base64.b64encode(digest).decode('utf-8')
auth_ctx['digest'] = encoded_digest
auth_ctx['next_operation'] = 'auth_agent_auth_response'
challenge_response = bin_bytes_buf(auth_ctx)
print(challenge_response)


# In[19]:


h = header(HeaderType.RODS_API_REQ.value, 
           challenge_response, 
           int_info=API_TABLE["AUTHENTICATION_APN"])
send_header(h, conn)
send_msg(challenge_response, conn)


# Once again, an `intInfo` of 0 is the auth framework's way of telling us that we've successfully authenticated. Decode the buf frame base64 if you'd like to double check the state of the auth context.

# In[20]:


h, m = recv(conn)


# # ils <a class="anchor" id="ils"></a>
# Next, let's perform an `ils`. The iCommands implementation does a little bit of verification, so we'll see how to perform object stat-ing, genQuery, and specQuery here.

# ## Stat a Collection <a class="anchor" id="stat_coll"></a>
# This step is necessary to make sure that the directory about to be ls'd actually exists.

# First, we'll have to generate a `DataObjInp_PI`. This is a generic message type used for all sorts of operations. It also contains a `KeyValPair_PI`, which is an important data structure in the iRODS protocol. Although it cannot be sent on its own, it is a very important vehicle for parameters. Internally, this `KeyValPair_PI` is a cond_input structure.

# In[21]:


def data_obj_inp(
    obj_path,
    create_mode="0",
    open_flags="0",
    offset="0",
    data_size="0",
    num_threads="0",
    opr_type="0",
    cond_input= {}
) -> bytes:
    obj_inp = ET.fromstring(f"""
    <DataObjInp_PI>
        <objPath>{obj_path}</objPath>
        <createMode>{create_mode}</createMode>
        <openFlags>{open_flags}</openFlags>
        <offset>{offset}</offset>
        <dataSize>{data_size}</dataSize>
        <numThreads>{num_threads}</numThreads>
        <oprType>{opr_type}</oprType>
    </DataObjInp_PI>
    """)
    ET.indent(obj_inp)
    obj_inp = append_kvp(obj_inp, cond_input)
    ret = ET.tostring(obj_inp).decode("utf-8").replace("\n", "").replace(" ", "").encode('utf-8')
    print(ret)
    return ret
    
def parse_key_val_pair_into_dict(kvp: ET):
    ret = {}

    return ret


# Next, we'll need some utility methods. How these work might not be totally obvious, so consider reading ahead and revisiting these once you've seen how it's used in the stat API Call.

# In[22]:


def append_kvp(et, data):
    kvp = ET.Element("KeyValPair_PI")
    sslen = ET.Element("ssLen")
    sslen.text = str(len(data))
    kvp.append(sslen)
    for key in data.keys():
        keyWord = ET.Element("keyWord")
        keyWord.text = key
        kvp.append(keyWord)
    for value in data.values():
        svalue = ET.Element("svalue")
        svalue.text = value
        kvp.append(svalue)
    et.append(kvp)
    return et

def append_iivp(et, data):
    iivp = ET.Element("InxIvalPair_PI")
    sslen = ET.Element("iiLen")
    sslen.text = str(len(data))
    iivp.append(sslen)
    for key in data.keys():
        inx = ET.Element("inx")
        inx.text = key
        iivp.append(inx)
    for value in data.values():
        ivalue = ET.Element("ivalue")
        ivalue.text = value
        iivp.append(ivalue)
    et.append(iivp)
    return et

def append_ivp(et, data):
    ivp = ET.Element("InxValPair_PI")
    islen = ET.Element("isLen")
    islen.text = str(len(data))
    ivp.append(islen)
    for key in data.keys():
        inx = ET.Element("inx")
        inx.text = key
        ivp.append(inx)
    for value in data.values():
        svalue = ET.Element("svalue")
        svalue.text = value
        ivp.append(svalue)
    et.append(ivp)
    return et


# In[23]:


stat_obj_inp = data_obj_inp("/tempZone/home/rods") 
h = header(HeaderType.RODS_API_REQ.value, 
           stat_obj_inp, 
           int_info=API_TABLE["OBJ_STAT_AN"])

send_header(h, conn)
send_msg(stat_obj_inp, conn)


# If everything has gone smoothely, you should receive a `RodsObjStat_PI` from the server. That `objType` is 2 tells us that the thing we stat'd was a collection. Since collections are purely virtual objects, `objSize` is 0.

# In[24]:


h, m = recv(conn)


# Now we know our target is there. Let's go ahead and read its contents. This happens through a genQuery. For details about the first-generation GenQuery API, see [here](https://github.com/irods/irods_docs/blob/main/docs/developers/library_examples.md#querying-the-catalog-using-general-queries). For information about the GenQuery2 interface (under development as of time of writing), see [here](https://www.youtube.com/watch?v=3dR_JoGA6wA&t=654s&ab_channel=TheiRODSConsortium).

# In[25]:


def gen_query(
    max_rows=256,
    continue_inx=0,
    partial_start_index=0,
    options=0,
    cond_input={},
    select_inp={},
    sql_cond_inp={}
) -> bytes:
    ret = ET.fromstring(f"""
    <GenQueryInp_PI>
        <maxRows>{max_rows}</maxRows>
        <continueInx>{continue_inx}</continueInx>
        <partialStartIndex>{partial_start_index}</partialStartIndex>
        <options>{options}</options>
    </GenQueryInp_PI>
    """)
    ret = append_kvp(ret, cond_input)
    ret = append_iivp(ret, select_inp)
    ret = append_ivp(ret, sql_cond_inp)
    
    return ET.tostring(ret).decode("utf-8").replace(" ", "").replace("\n", "").encode("utf-8")

## The Catalog ships with a table of SQL functions that can perform common functions
## The first link above also has an example of a specific query.
def spec_query(
    sql,
    arg_1,
    max_rows=256,
    continue_inx=0,
    row_offset=0,
    options=0,
    cond_input={}
) -> bytes:
    ret = ET.fromstring(f"""
    <specificQueryInp_PI>
        <sql>{sql}</sql>
        <arg1>{arg_1}</arg1>
        <maxRows>{max_rows}</maxRows>
        <continueInx>{continue_inx}</continueInx>
        <rowOffset>{row_offset}</rowOffset>
        <options>{options}</options>
    </specificQueryInp_PI>
    """)
    ret = append_kvp(ret, cond_input)
    
    return ET.tostring(ret).decode("utf-8").replace(" ", "").replace("\n", "").encode("utf-8")


# In[26]:


## This query grabs the inheritance flag of the target collection
gq = gen_query(
    cond_input={"zone":"tempZone"},
    select_inp={
        CATALOG_INDEX_TABLE["COL_COLL_INHERITANCE"]:"1"
    },
    sql_cond_inp={
        CATALOG_INDX_TABLE["COL_COLL_NAME"]:"= '/tempZone/home/rods'"
    }
)
print(gq)


# *NB:* It might be easier to make sense of the server's response if you make sure the directory you're about to stat is populated.

# One quick thing before we send this over to the server: the iRODS dialect of XML has a few quirks related to encoding special characters. Some special characters it does not escape at all. For others, it uses a non-standard encoding. For that reason, we'll need to write some functions that translate between standard XML and iRODS XML.

# In[27]:


standard_to_irods = {
  b"&#34;":b"&quot;",
    
  b"&#39;":b"&apos;",
    
  b"&#x9;":b"\t",
    
  b"&#xD;":b"\r",
    
  b"&#xA;":b"\n",
    
  b"`"    :b"&apos"
}


def translate_xml_to_irods_dialect(xml_bytes):
    output = b''
    return xml_bytes
    while len(xml_bytes) > 0:
        for prefix in standard_to_irods:
            if len(xml_bytes) == 0:
                break
            if xml_bytes.startswith(prefix):
                output += standard_to_irods[prefix]
                xml_bytes = xml_bytes[len(prefix):]
            else:
                output += bytes(xml_bytes[0])
                xml_bytes = xml_bytes[1:]
    return output
    
gq = translate_xml_to_irods_dialect(gq)
h = header(HeaderType.RODS_API_REQ.value, 
           gq, 
           int_info=API_TABLE["GEN_QUERY_AN"])


# In[28]:


send_header(h, conn)
send_msg(gq, conn)


# The results from this GenQuery might be a little hard to grok. 

# In[29]:


h, m = recv(conn)


# To demonstrate how they amount to valid SQL results, let's translate these into a Pandas DataFrame. To see a similar example in C++ that operates above the protocol level, refer to the genQuery1 documentation linked above.

# In[ ]:


def read_gen_query_results_into_dataframe(gqr: bytes):    
    gqr = ET.fromstring(gqr.decode('utf-8'))
    
    ## Each SqlResult_PI is a row of data
    ## Collect them all into a list
    ## We can safely ignore the "reslen" attribute since the Python XML 
    ## API already knows how large each string is, but you might use it for error checking
    results = [result.find("value").text for result in gqr.findall("SqlResult_PI")]
    
    df = pd.DataFrame()
    
    row_cnt = int(gqr.find("rowCnt").text)
    attribute_cnt = int(gqr.find("attriCnt").text)
    
    for result in gqr.findall("SqlResult_PI"):
        attri_inx = int(result.find("attriInx").text)
        res_len = int(result.find("reslen").text)
        value = result.find("value").text
            
            
    return df


# In[ ]:


## This genQuery grabs the actual data objects 
## that live in the collection we care about
gq = gen_query(
    select_inp={
        CATALOG_INDEX_TABLE["COL_COLL_INHERITANCE"]:"1"
    },
    sql_cond_inp={
        CATALOG_INDEX_TABLE["COL_COLL_NAME"]:"= 'rods'", 
        CATALOG_INDEX_TABLE["COL_DATA_NAME"]:"= '/tempZone/home'"
    }
)
print(gq)


# In[ ]:


def disconnect(sock):
    sock.send(
        header(HeaderType.RODS_DISCONNECT.value, "") ## Empty string so msgLen is 0
    )


# In[ ]:


disconnect(conn)
conn.close()


# In[ ]:





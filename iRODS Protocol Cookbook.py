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

# In[1]:


## We'll be doing this from scratch, so all imports will come from 
## the Python standard library
import socket
import struct
import base64
import json
import hashlib
import time
import enum
import xml.etree.ElementTree as ET
from enum import Enum


# This tutorial assumes you have deployed iRODS in Docker using
# the script stand_it_up.py from the iRODS Testing Environment, 
# which can be found on Github [here](https://github.com/irods/irods_testing_environment)
# To find the IP address associated with your Docker container, you can run this one-liner:
# ```bash
# docker inspect   -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ubuntu-2004-postgres-1012_irods-catalog-provider_1
# ```
# Otherwise, if want to try this out on a real-world zone, insert that zone's hostname here.

# In[2]:


HOST = "172.19.0.3"


# In[3]:


PORT = 1247 ## This is the standard iRODS port
MAX_PASSWORD_LENGTH = 50 ## This constant comes 
                         ## from the internals 
                         ## of the iRODS server


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

def header(header_type: HeaderType, msg: bytes, error_len=0, bs_len=0, int_info=0):
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


def send_header(header, sock):
    header_len = int.to_bytes(len(header), byteorder='big', length=4) ## The first part of all iRODS messages
                                                                      ## must be 4 bytes indicating how long
                                                                      ## the header is in bytes. These bytes
                                                                      ## and the entire integer must be transmitted
                                                                      ## in big-endian order
    print(header_len)
    sock.sendall(header_len)
    sock.sendall(header)
    
def send_msg(msg, sock) -> None:
    sock.sendall(msg)
    
def recv(sock) -> [ET, ET]:
    header_len = int.from_bytes(sock.recv(4), byteorder='big')
    print(f"HEADER LEN: [{header_len}]")
    is st
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
                ) -> str:
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


def encode_dict_as_base64_json(d): 
    return base64.b64encode(
        json.dumps(d).encode('utf-8'))


# The payload is decoded because otherwise Python will 
# add extra characters to give a string representation of the bytes object

# In[13]:


def read_base64_into_json(bsix, trunc=False):
    decoded = base64.b64decode(bsix).decode('utf-8')
    return json.loads(decoded[:-1]) if trunc else json.loads(decoded)

def bin_bytes_buf(payload):
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


AUTHENTICATION_APN = 110000 ## The API number for the 4.3.0 auth framework
initial_auth_msg = bin_bytes_buf(auth_ctx)
print(initial_auth_msg)
h = header(HeaderType.RODS_API_REQ.value, 
           initial_auth_msg, 
           int_info=AUTHENTICATION_APN)
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


def pad_password(pw):
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


h = header(HeaderType.RODS_API_REQ.value, challenge_response, int_info=AUTHENTICATION_APN)
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

# In[ ]:


def data_obj_inp(
    obj_path,
    create_mode=0,
    open_flags=0,
    offset=0,
    data_size=0,
    num_threads=0,
    opr_type=0,
    cond_input: dict = {}
):
    data_obj_inp = ET.fromstring(f"""
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
    
    kvp = ET.Element("KeyValPair_PI")
    kvp.append(
        ET.Element("sslen", text=len(cond_input))
    )
    for key in cond_input.keys():
        kvp.append(
            ET.Element("keyWord", text=key)
        )
    for value in cond_input.values():
        kvp.append(
            ET.Element("svalue", text=value)
        )
    
    data_obj_inp.find("DataObjInp_PI").append(kvp)
    return data_obj_inp.dump()
    
def parse_key_val_pair_into_dict(kvp):
    kvp = ET.fromstring(kvp)
    


# In[21]:


def disconnect(sock):
    sock.send(
        header(HeaderType.RODS_DISCONNECT.value, "") ## Empty string so msgLen is 0
    )


# In[22]:


disconnect(conn)
conn.close()


# In[ ]:





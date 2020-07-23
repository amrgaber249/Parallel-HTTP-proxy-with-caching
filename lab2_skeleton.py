# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
from _thread import *
import time

from email.utils import formatdate

class HttpRequestInfo(object):
    """
    Represents a HTTP request information
    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.
    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.
    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.
    requested_host: the requested website, the remote website
    we want to visit.
    requested_port: port of the webserver we want to visit.
    requested_path: path of the requested resource, without
    including the website name.
    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:
        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n
        (just join the already existing fields by \r\n)
        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        STR = self.method + " " + self.requested_path + " HTTP/1.0\r\n"
        STR += "Host: "+self.requested_host+"\r\n"
        if self.headers:
            for h in self.headers[1:]:
                STR += h[0]+": "+h[1]+"\r\n"
        STR += "\r\n"

        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        return STR

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Path: ",self.requested_path)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above """
        STR = "HTTP/1.0 "+str(self.code) +" "+self.message+"\r\n"
        STR += "Date: " + formatdate(timeval=None,
                                     localtime=False, usegmt=True)+"\r\n"
        STR += "Connection: Closed"+"\r\n"
        STR += "\r\n"
        
        return STR

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.
    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.
    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """
    cache = {}
    Proxy_Socket = setup_sockets(proxy_port_number)

    while True:
        C_Socket,Addr = Proxy_Socket.accept()
        start_new_thread(new_client,(C_Socket,cache,Addr))
        
    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    return None

def new_client(C_Socket,cache,Addr):


    message_list=[]
    while True:
        request_msg = C_Socket.recvfrom(1024)
        try:
            message_list.append(request_msg[0].decode('UTF-8'))
        except:
            C_Socket.close()
            break

        # Check if Double enter or The Connection Lost (length of received message equal to zero)
        if request_msg[0]==b'':
            break
        elif request_msg[0] == b'\r\n':
            message_list="".join(message_list)
            SRC_ADDR = Addr
            
            request_data = http_request_pipeline(SRC_ADDR,message_list)
            if isinstance(request_data,HttpRequestInfo):
                key = request_data.method+" "+request_data.requested_host+"/"+request_data.requested_path+":"+request_data.requested_port
                if cache.get(key,0):
                    print("***FROM CACHE***")
                    rev_data = cache.get(key)
                else:
                    rev_data = response_proxy(request_data)
                    rev_data = rev_data.encode('UTF-8')
                    cache[key]= rev_data
            else: 
                rev_data = request_data.to_http_string()
                rev_data = request_data.to_byte_array(rev_data)

            C_Socket.send(rev_data)
            C_Socket.close()
            break


def response_proxy(request_data):

    """
    Sending to Request Server
     
    """
    print("************** NOW ENTERING SENDING **************")
    P_Socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        IP = socket.gethostbyname(request_data.requested_host)
        print(IP)
        P_Socket.connect((IP, int(request_data.requested_port)))
        print("************** Connecting Sucessfully **************")
        P_Socket.send(request_data.to_byte_array(request_data.to_http_string()))
        print("************** Send Successfully **************")
        while True:
            full_msg = ''
            while True:
                msg = P_Socket.recv(1024)
                if len(msg) <= 0:
                    break
                full_msg += msg.decode("utf-8")

            if len(full_msg) > 0:
                # print(full_msg)
                break
    except:
        full_msg = HttpErrorResponse(404,"Page Not Found").to_http_string()
    P_Socket.close()
    return full_msg



def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.
    But feel free to add your own classes/functions.
    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)

    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.

    P_Socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    P_Socket.bind(("127.0.0.1",proxy_port_number))
    P_Socket.listen(15)
    
    print("*" * 50)
    print("[setup_sockets] Implement me!")
    print("*" * 50)
    return P_Socket



def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.
    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo
    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.
    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request

    # http_raw_data = parsing_http_raw_data(http_raw_data)
    # print(http_raw_data)
    
    validity = check_http_request_validity(http_raw_data)
    print("CHECK HERE ",validity)

    if validity != HttpRequestState.GOOD:
        if validity == HttpRequestState.NOT_SUPPORTED:
            code = 501
            message = "Not Implemented"
        else:
            code = 400
            message = "Bad Request"
        err = HttpErrorResponse(code, message)
        return err

    else:
        HTTP_OBJ = parse_http_request(source_addr,http_raw_data)
    # Return error if needed, then:
    # parse_http_request()
    # sanitize_http_request()
    # Validate, sanitize, return Http object.

    request_byte = sanitize_http_request(HTTP_OBJ)

    print("*" * 50)
    print("[http_request_pipeline] Implement me!")
    print("*" * 50)
    return request_byte


def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """
    http_raw_data = parsing_http_raw_data(http_raw_data)
    print("*" * 50)
    print("[parse_http_request] Implement me!")
    print("*" * 50)
    # Replace this line with the correct values.
    ret = HttpRequestInfo(source_addr, http_raw_data["method"], http_raw_data["host"],http_raw_data["port"],
                                                                                    http_raw_data["path"],http_raw_data["header"])
    return ret


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid
    returns:
    One of values in HttpRequestState
    """
    http_raw_data = parsing_http_raw_data(http_raw_data)
    print(http_raw_data)
    if http_raw_data["host"]=="":
        print("1")
        return HttpRequestState.INVALID_INPUT

    for header in http_raw_data["header"]:
        if header != [""] and len(header)==1:
            print("2")
            return HttpRequestState.INVALID_INPUT
            
    if http_raw_data["version"].lower() not in ["http/1.0", "http/1.1"]:
        print("3")
        return HttpRequestState.INVALID_INPUT
    if http_raw_data["method"].lower() in ['put','head','post']:
        return HttpRequestState.NOT_SUPPORTED

    elif http_raw_data["method"].lower() not in ["get"]:
        print("4")
        return HttpRequestState.INVALID_INPUT
    


    print("*" * 50)
    print("[check_http_request_validity] Implement me!")
    print("*" * 50)
    # return HttpRequestState.GOOD (for example)

    return HttpRequestState.GOOD


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.
    for example, expand a full URL to relative path + Host header.
    returns:
    nothing, but modifies the input object
    """
    print("*" * 50)
    print("[sanitize_http_request] Implement me!")
    print("*" * 50)
    http_string = request_info.to_http_string()
    pass

    return request_info

def parsing_http_raw_data(http_raw_data):
    """
    Parse http_raw_data 

    """
    host=""
    try:
        http_raw_data = http_raw_data.split("\r\n")[:-1]
        request_line = http_raw_data[0].split(" ")
        if len(request_line)>3:
            raise ValueError
        header_lines = http_raw_data[1:]
        url = request_line[1]
        headers=[]
        for header in header_lines:
            if header.startswith("Host: "):
                host=header.split(": ")[1]
            headers.append(header.split(": "))

        if url.startswith("http"):
            _,_,url = url.partition("://")

        if not url.startswith('/'):
            
            if '/' in url:
                host,path = url.split("/",1)
                path= "/"+path 
            else:
                host = url
                path = "/"

        else:
            path = url


        if ':'in host:
            host,port = host.split(":")
        else:
            port = "80"
        http_version = request_line[2]

        if len(headers)>1 and headers[-1]==['']:
            headers= headers[:-1]
        elif len(headers)==1 and headers[-1]==['']:
            headers.pop()
            


        request_data ={
            "method"    : request_line[0],
            "path"      : path,
            "version"   : http_version,
            "host"      : host,
            "port"      : port,
            "header"    : headers
        }
    except: 
        request_data={
            "method"    : "",
            "path"      : "",
            "version"   : "",
            "host"      : "",
            "port"      : "",
            "header"    : ""                
        }

    return request_data

#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*
    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.
    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
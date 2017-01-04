#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import sys
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import os.path
import os
import hashlib

class UAclient(ContentHandler):
    """
    Class to extract data from xml file (config)
    """
    
    def __init__ (self):
    
        self.name = ''
        self.passwd = ''
        self.IPserv = ''
        self.PORTserv = ''
        self.IPpr = ''
        self.PORTpr = ''

    def startElement(self, name, attrs):
        
        if name == 'account':
            self.name = attrs.get('username','')
            self.passwd = attrs.get('passwd', '')
            print('User:           ' + self.name + ' >< ' + self.passwd)
        elif name == 'uaserver':
            self.IPserv = attrs.get('ip','')
            self.PORTserv = attrs.get('puerto','')
            print('Serving part:   ' + self.IPserv + ' >< ' + self.PORTserv)
      #  elif name == 'rtpaudio':
        elif name == 'regproxy':
            self.IPpr = attrs.get('ip','')
            self.PORTpr = attrs.get('puerto','')
            print('Proxy:          ' + self.IPpr + ' >< ' + self.PORTpr)
      #  elif name == 'log':
      #  elif name == 'audio':
        
        
        
        
        

            
    
if __name__ == "__main__":
    
    #------->
    LINE = sys.argv[1:]
    try:
        config_file = LINE[0]
        method = LINE[1]
        if method not in ['register', 'invite', 'bye']:
            sys.exit('\nUsage: python3 uaclient.py config method option\n')  
        elif method == 'register':
            option = int(LINE[2])
        else:
            option = LINE[2]
    except:
        sys.exit('\nUsage: python3 uaclient.py config method option\n')
        
    # Verify that the config file exists
    if os.path.isfile(config_file):
        print('\nConfigFile/Method/Option: ', LINE, '\n')
    else:
        sys.exit('\n' + '<' + config_file + '> File not found.' + '\n')
#-------Error al meter parametros y si no encuentra el fichero hecho----

    # XML data searcher
    parser = make_parser() 
    TAGhandler = UAclient()
    parser.setContentHandler(TAGhandler)
    parser.parse(open(config_file))
    
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((TAGhandler.IPpr, int(TAGhandler.PORTpr)))
    
    if method == 'register':
        data = method.upper() + ' sip:' + TAGhandler.name + ':' \
               + TAGhandler.PORTserv + ' SIP/2.0\r\n' + 'Expires: ' \
               + str(option) + '\r\n\r\n' 
        
        print('\n' + "Sending:\n" + data)
        my_socket.send(bytes(data, 'utf-8'))
    
        #Error conexion-----------------
        #try:
        rec_data = my_socket.recv(1024).decode('utf-8')
        #except ConnectionRefusedError:
        #sys.exit('20101018160243 Error: No server listening at 127.0.0.1 port \
        #              20000')
                  
        print('Received:\n' + rec_data)
            
        if rec_data.split(' ')[1] == '401':
            nonce = rec_data.split(' ')[5][rec_data.split(' ')[5].find('"')\
            +1:-5]
            #We create a response:
            m = hashlib.sha1()
            m.update(bytes(TAGhandler.passwd,'utf-8'))
            m.update(bytes(nonce,'utf-8'))
            response = m.hexdigest()
            
                #Comparar el response, envio un numero solo
            aut_data = method.upper() + ' sip:' + TAGhandler.name + ':' \
                       + TAGhandler.PORTserv + ' SIP/2.0\r\n' + 'Expires: ' \
                       + str(option) + '\r\n' + 'Authorization: ' + \
                       str(response) + '\r\n\r\n' 
            print('Sending authentication:\n' + aut_data)
            my_socket.send(bytes(aut_data, 'utf-8')) #es el nonce del proxy
            
            print('Received:\n' + my_socket.recv(1024).decode('utf-8'))
            
    if method == 'invite':
        
        #body = 'v=0\r\no=' + 
        data = method.upper() + ' sip:' + option + ' SIP/2.0\r\n' +\
               'Content-Type: application/sdp\r\n'
               #se en via el option despues del sip, que es el correo
        print('\n' + "Sending:\n" + data)
        my_socket.send(bytes(data, 'utf-8'))
        
        
        
        






    print('Finished socket.\n')
    my_socket.close()    

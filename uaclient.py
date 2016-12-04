#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import sys
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import os.path
import os

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
            print('User:    ' + self.name + ' >< ' + self.passwd)
        elif name == 'uaserver':
            self.IPserv = attrs.get('ip','')
            self.PORTserv = attrs.get('puerto','')
            print('Serving part:  ' + self.IPserv + ' >< ' + self.PORTserv)
      #  elif name == 'rtpaudio':
        elif name == 'regproxy':
            self.IPpr = attrs.get('ip','')
            self.PORTpr = attrs.get('puerto','')
            print('Proxy:   ' + self.IPpr + ' >< ' + self.PORTpr)            
      #  elif name == 'log':
      #  elif name == 'audio':
        
        
        

            
    
if __name__ == "__main__":
    
    #------->
    LINE = sys.argv[1:]
    try:
        config_file = LINE[0]
        method = LINE[1]
    except:
        sys.exit('\nUsage: python3 uaclient.py config method option\n')
        
    # Verify that the config file exists
    if os.path.isfile(config_file):
        print('\nConfigFile/Method: ', LINE, '\n')
    else:
        sys.exit('\n' + '<' + config_file + '> File not found.' + '\n')
#-------Error al meter parametros y si no encuentra el fichero hecho----

    # XML data searcher
    parser = make_parser() 
    TAGhandler = UAclient()
    parser.setContentHandler(TAGhandler)
    parser.parse(open(config_file))
    
    
    data = method.upper() + ' sip:' + TAGhandler.name + ':<PORT??> ' + 'SIP/2.0' 
    
    
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((TAGhandler.IPpr, int(TAGhandler.PORTpr)))

    print('\n' + "Sending: " + data)
    my_socket.send(bytes(data, 'utf-8'))






    print('\nFinished socket\n')
    my_socket.close()    

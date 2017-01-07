#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import os.path
import os
import socketserver
import socket

class UAserver(ContentHandler):
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
            print('\nUser:           ' + self.name + ' >< ' + self.passwd)
        elif name == 'uaserver':
            self.IPserv = attrs.get('ip','')
            self.PORTserv = attrs.get('puerto','')
            print('Serving part:   ' + self.IPserv + ' >< ' + self.PORTserv)
      #  elif name == 'rtpaudio':
        elif name == 'regproxy':
            self.IPpr = attrs.get('ip','')
            self.PORTpr = attrs.get('puerto','')
            print('Proxy:          ' + self.IPpr + ' >< ' + self.PORTpr + '\n')
      #  elif name == 'log':
      #  elif name == 'audio':
      
class ServHandler(socketserver.DatagramRequestHandler): 
    '''
    For each petition.
    '''
    
    def handle(self):
        
        #self.json2registered()
        
        rec_data = self.rfile.read().decode('utf-8') #en todo lo recibido
        
        print('Received:\n' + rec_data)






if __name__ == "__main__":

    LINE = sys.argv[1:]
    try:
        config_file = LINE[0]
        
    except:
        sys.exit('\nUsage: python3 server.py config\n')
        
    # Verify that the config file exists
    if os.path.isfile(config_file):
        parser = make_parser() 
        TAGhandler = UAserver()
        parser.setContentHandler(TAGhandler)
        parser.parse(open(config_file))        
    else:
        sys.exit('\n' + '<' + config_file + '> File not found.' + '\n')
        
        
        
    serv = socketserver.UDPServer((TAGhandler.IPserv, int(TAGhandler.PORTserv)),
                                   ServHandler)
    print('\nListening...\n')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print(" ---> Finished Server.")
        
    

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
        elif name == 'rtpaudio':
            self.PORTrtp = attrs.get('puerto', '')
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
        
        method = rec_data.split(' ')[0]
        client = rec_data.split(' ')[1]
        
        Trying = 'SIP/2.0 100 Trying\r\n\r\n'
        Ring = 'SIP/2.0 180 Ring\r\n\r\n'
        OK = 'SIP/2.0 200 OK\r\nContent-Type: application/sdp\r\n\r\n' +\
             'v=0\r\no=' + TAGhandler.name + ' 127.0.0.1\r\ns=Session\r\n' +\
             't=0\r\nm=audio ' + TAGhandler.PORTrtp + ' RTP\r\n\r\n'
        
        if method == 'INVITE':
            print('Sending Trying...\n')
            self.wfile.write(bytes(Trying + Ring + OK, 'utf-8'))
            
        if method == 'ACK':
            print('RTP---------------------')
            
        
        #if method == 'BYE':
        






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
        print(" ---> Finished User Agent Server.")
        
    

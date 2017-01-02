#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import socketserver
import socket
import json
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import os
import os.path

class ProxyParser(ContentHandler):

    def __init__ (self):
    
        self.NAMEreg = ''
        self.IPreg = ''        
        self.PORTreg = ''

    def startElement(self, name, attrs):
        ''' Attrs of XML file searcher '''
        
        if name == 'server':
            self.NAMEreg = attrs.get('name','')
            self.IPreg = attrs.get('ip', '')
            self.PORTreg = attrs.get('puerto', '')
            print('Server: ' + self.NAMEreg + ' >< ' + self.IPreg + ' >< '
                  + self.PORTreg)
      #  elif name == 'database':        
      #  elif name == 'log':
      
class ProxyReceivHandler(socketserver.DatagramRequestHandler):     

    def handle(self):

        print('------- RECEIVED: -------')
        rec_data = self.rfile.read().decode('utf-8')
        print(rec_data.split(' '))
                
        print('\nClient sends us:\n' + rec_data)
       
        if rec_data.split(' ')[0] == 'REGISTER':
            if len(rec_data.split(' ')) <= 4:
            
                nonce = 8989898989898989
                Aut_data = 'SIP/2.0 401 Unauthorized\r\nWWW Authenticate: ' \
                           + 'Digest nonce="' + str(nonce) + '"'
                print('Unauthorized REGISTER. Sending nonce...')
                self.wfile.write(bytes(Aut_data, 'utf-8'))
                
               
            elif len(rec_data.split(' ')) > 4:
                if rec_data.split(' ')[3][rec_data.split(' ')[3].find('A'):] \
                   == 'Authorized:':
                    print('hei')             
                    
  


    
if __name__ == "__main__":

#------->
    try:
        config_file = sys.argv[1]
    except:
        sys.exit('\nUsage: python3 proxy_registrar.py config\n')
        
    if os.path.isfile(config_file):
        print('\nConfigFile:', config_file, '\n')        
    else:
        sys.exit('\n' + '<' + sys.argv[1] + '> File not found.' + '\n')
#-------Error al meter parametros y si no encuentra el fichero hecho----
        
    parser = make_parser() 
    TAGhandler = ProxyParser()
    parser.setContentHandler(TAGhandler)
    parser.parse(open(config_file))
    
    serv = socketserver.UDPServer((TAGhandler.IPreg, int(TAGhandler.PORTreg)),
                                   ProxyReceivHandler)
    print('\nServer ' + TAGhandler.NAMEreg + ' listening at port '
          + TAGhandler.PORTreg + '...\n')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print(" ---> Finished Proxy-Registrar Server.")
        
        
    
        
        
        
        
        
        

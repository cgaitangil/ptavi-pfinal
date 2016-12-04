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

        data = self.rfile.read().decode('utf-8')
        print("Client sends us:  " + data + '\n')
  


    
if __name__ == "__main__":

#------->
    try:
        config_file = sys.argv[1]
    except:
        sys.exit('\nUsage: python3 proxy_registrar.py config\n')
        
    if os.path.isfile(config_file):
        print('\nConfigFile: ', config_file, '\n')        
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
        
        
    
        
        
        
        
        
        

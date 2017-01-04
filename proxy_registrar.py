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
import hashlib

class ProxyParser(ContentHandler):

    def __init__ (self):
    
        self.NAMEreg = ''
        self.IPreg = ''        
        self.PORTreg = ''
        #self.users 
        self.psswds = ''

    def startElement(self, name, attrs):
        ''' Attrs of XML file searcher '''
        
        if name == 'server':
            self.NAMEreg = attrs.get('name','')
            self.IPreg = attrs.get('ip', '')
            self.PORTreg = attrs.get('puerto', '')
            print('ServerProxy: ' + self.NAMEreg + ' >< ' + self.IPreg + ' >< '
                  + self.PORTreg)
        elif name == 'database':
            #self. = attrs.get('path', '')
            self.psswds = attrs.get('passwdpath', '')       
      #  elif name == 'log':
      
class ProxyReceivHandler(socketserver.DatagramRequestHandler): 
    '''
    For each petition.
    '''
    
    Users = {}

    def handle(self):
        
        self.json2registered()
        
        rec_data = self.rfile.read().decode('utf-8') #en todo lo recibido
        
        print('\nClient sends us:\n' + rec_data)
       
        if rec_data.split(' ')[0] == 'REGISTER':
        
            nonce = 8989898989898989
            
            ua = rec_data.split(' ')[1][4:rec_data.split(' ')[1].rfind(':')]
            expires = rec_data.split(' ')[3][:rec_data.split(' ')\
                      [3].find('\r')]
                      
            if expires == '0': 
                try:
                    del self.Users[ua]
                    print('<' + ua + '> has been deleted.') 
                    self.wfile.write(b'User removed.')
                except KeyError:
                    print('Error: User to delete not found in REGISTER')
                    self.wfile.write(b'Error: User to delete not found\n')
                      
                print('\n----------------------------------------')
                print(rec_data.split(' '))
                print(' ')
                print(self.Users)
                print('----------------------------------------\n')
                    
            else:
            
                if len(rec_data.split(' ')) <= 4:
                    Aut_data = 'SIP/2.0 401 Unauthorized\r\nWWW ' +\
                               'Authenticate: ' + 'Digest nonce="' +\
                                str(nonce) + '"\r\n\r\n'
                    print('Unauthorized REGISTER. Sending nonce...')
                    self.wfile.write(bytes(Aut_data, 'utf-8'))
                
                elif len(rec_data.split(' ')) > 4:
                
                    if rec_data.split(' ')[3][rec_data.split(' ')[3].find('A')\
                       :] == 'Authorization:':
                   
                        resp = rec_data.split(' ')[-1][:rec_data.split(' ')\
                               [-1].find('\r')]
                    
                        f = open(TAGhandler.psswds, 'r')
                        for line in f.readlines():
                            if ua == line.split(':')[0]:
                    
                                passwd = line.split(':')[1][:-1]
                                m = hashlib.sha1()
                                m.update(bytes(str(passwd),'utf-8'))
                                m.update(bytes(str(nonce),'utf-8'))
                                comp_response = m.hexdigest()
                                  
                                expires = str(time.strftime('%Y-%m-%d %H:%M:%S'\
                                                            ,time.gmtime\
                                                            (time.time()))) +\
                                                            ' +' + expires
                                if resp == comp_response:
                                    OK = 'SIP/2.0 200 OK\r\n\r\n'
                                    self.wfile.write(bytes(OK, 'utf-8'))   
                                    print('Authentication done. Sending OK...')
                                    print('Adding User... ' + ua)
                                    self.Users[ua] = {'address':\
                                                      self.client_address[0],\
                                                      'expires': expires}
  
                    print('\n----------------------------------------')
                    print(rec_data.split(' '))
                    print(' ')
                    print(self.Users)
                    for user in self.Users:
                        print(user)
                    
                    print('----------------------------------------\n')
        
        self.register2json()
        
    def register2json(self):
        '''Update json file'''

        json.dump(self.Users, open('registered.json', 'w'), indent=4)
        
    def json2registered(self):
        '''Loader json (users) file'''

        with open('registered.json') as fich:
            try:
                self.Users = json.load(fich)
            except:
                pass
                        
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
        
        
    
        
        
        
        
        
        

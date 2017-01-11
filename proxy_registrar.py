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

    def __init__(self):

        self.NAMEreg = ''
        self.IPreg = ''
        self.PORTreg = ''
        # self.users
        self.psswds = ''

    def startElement(self, name, attrs):
        ''' Attrs of XML file searcher '''

        if name == 'server':
            self.NAMEreg = attrs.get('name', '')
            self.IPreg = attrs.get('ip', '')
            self.PORTreg = attrs.get('puerto', '')
            print('ServerProxy: ' + self.NAMEreg + ' >< ' + self.IPreg +
                  ' >< ' + self.PORTreg)
        elif name == 'database':
            self.database = attrs.get('path', '')
            self.psswds = attrs.get('passwdpath', '')
        elif name == 'log':
            self.log = attrs.get('path', '')


def log(config, text):
    """Event logging method."""

    with open(config.log, 'a') as f:
        if text[0] == '-':
            now = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
            text = text.replace('\r\n', ' ') + '\r\n'
            f.write(text)
        else:
            now = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
            text = now + ' ' + text.replace('\r\n', ' ') + '\r\n'
            f.write(text)


class ProxyReceivHandler(socketserver.DatagramRequestHandler):
    '''
    For each petition.
    '''

    Users = {}
    port_to_log = {}  # uaserver : 'port'

    def handle(self):

        self.json2registered()

        rec_data = self.rfile.read().decode('utf-8')

        print('\nClient sends us:\n' + rec_data)

        method = rec_data.split(' ')[0]
        if method == 'REGISTER':

            ua = rec_data.split(' ')[1][4:rec_data.split(' ')[1].rfind(':')]
            port = rec_data.split(' ')[1][rec_data.split(' ')[1]
                                          .rfind(':')+1:]

            self.port_to_log[ua] = port  # Do registers before invite

            # log:
            text = 'Received from ' + self.client_address[0] + ':' +\
                   str(self.client_address[1]) + ': ' + rec_data
            log(TAGhandler, text)

            nonce = 8989898989898989

            expires = rec_data.split(' ')[3][:rec_data.split(' ')[3]
                                             .find('\r')]

            if expires == '0':
                try:
                    del self.Users[ua]
                    print('<' + ua + '> has been deleted.')
                    self.wfile.write(b'SIP/2.0 200 OK\r\n\r\n')

                    # log:
                    text = 'Sent to ' + self.client_address[0] + ':' +\
                           str(self.client_address[1]) + ': ' +\
                           'SIP/2.0 200 OK\r\n\r\n.'
                    log(TAGhandler, text)
                    text = '--------------------------------------------'
                    log(TAGhandler, text)

                except KeyError:
                    print('Error: User to delete not found. Sending 404...')
                    self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')

                    # log:
                    text = 'Sent to ' + self.client_address[0] + ':' +\
                           str(self.client_address[1]) + ': ' +\
                           'SIP/2.0 404 User Not Found\r\n\r\n'
                    log(TAGhandler, text)
                    text = '--------------------------------------------'
                    log(TAGhandler, text)

            else:

                Aut_data = 'SIP/2.0 401 Unauthorized\r\nWWW-' +\
                    'Authenticate: ' + 'Digest nonce="' +\
                    str(nonce) + '"\r\n\r\n'

                if len(rec_data.split(' ')) <= 4:
                    print('Unauthorized REGISTER. Sending nonce...')
                    self.wfile.write(bytes(Aut_data, 'utf-8'))

                    # log:
                    text = 'Sent to ' + self.client_address[0] + ':' +\
                           str(self.client_address[1]) + ': ' + Aut_data
                    log(TAGhandler, text)

                elif len(rec_data.split(' ')) > 4:

                    if rec_data.split(' ')[3][rec_data.split(' ')[3]
                                              .find('A'):] == 'Authorization:':

                        resp = rec_data.split(' ')[-1][:rec_data.split(' ')
                                                       [-1].find('\r')]

                        f = open(TAGhandler.psswds, 'r')
                        for line in f.readlines():
                            if ua == line.split(':')[0]:

                                passwd = line.split(':')[1][:-1]
                                m = hashlib.sha1()
                                m.update(bytes(str(passwd), 'utf-8'))
                                m.update(bytes(str(nonce), 'utf-8'))
                                comp_response = m.hexdigest()

                                expires = str(time.strftime
                                              ('%Y-%m-%d %H:%M:%S',
                                               time.gmtime(time.time()))) +\
                                    ' +' + expires

                                if resp == comp_response:
                                    OK = 'SIP/2.0 200 OK\r\n\r\n'
                                    self.wfile.write(bytes(OK, 'utf-8'))
                                    print('Authentication done. Sending OK...')
                                    print('Adding User... ' + ua)
                                    self.Users[ua] = {'address':
                                                      self.client_address[0],
                                                      'expires': expires,
                                                      'port':
                                                      self.client_address[1]}

                                    # log:
                                    text = 'Sent to ' +\
                                        self.client_address[0] + ':' +\
                                        str(self.client_address[1]) +\
                                        ': ' + OK
                                    log(TAGhandler, text)
                                    text = '-----------------------------' +\
                                           '---------------'
                                    log(TAGhandler, text)

                                else:
                                    print('Unauthorized REGISTER.')
                                    self.wfile.write(bytes(Aut_data, 'utf-8'))

                                    # log:
                                    text = 'Sent to ' +\
                                        self.client_address[0] + ':' +\
                                        str(self.client_address[1]) +\
                                        ': ' + Aut_data
                                    log(TAGhandler, text)

        if method == 'INVITE':

            # log:
            text = 'Received from ' + self.client_address[0] + ':' +\
                   str(self.client_address[1]) + ': ' + rec_data
            log(TAGhandler, text)

            client = rec_data.split(' ')[3][rec_data.split(' ')[3]
                                            .rfind('=')+1:]
            server = rec_data.split(' ')[1][rec_data.split(' ')[1]
                                            .find(':')+1:]

            print('Client:', client, '/ Server:', server + '\n')

            ClReg = False
            for user in self.Users:
                if user == client:
                    ClReg = True
                    print('Invite sender <' + client + '> is registered.')

            if ClReg is False:
                print('Invite sender <' + client + '> is not registered.' +
                      ' Sending 404...')
                self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')

                # log:
                text = 'Sent to ' + self.client_address[0] + ':' +\
                       str(self.client_address[1]) + ': ' +\
                       'SIP/2.0 404 User Not Found\r\n\r\n'
                log(TAGhandler, text)
                text = '--------------------------------------------'
                log(TAGhandler, text)

            else:
                SerReg = False
                for user in self.Users:
                    if user == server:
                        SerReg = True
                        print('Invite receiver <' + server +
                              '> is registered.')
                        print('Resending invite...')

                        my_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET,
                                             socket.SO_REUSEADDR, 1)
                        if server == 'jesse@pinkman.com':
                            my_socket.connect((self.Users[user]['address'],
                                               2222))
                        if server == 'walter@white.com':
                            my_socket.connect((self.Users[user]['address'],
                                               1112))
                        my_socket.send(bytes(rec_data, 'utf-8'))

                        # log:
                        text = 'Sent to 127.0.0.1:' +\
                            self.port_to_log[server] + ': ' + rec_data
                        log(TAGhandler, text)

                        serv_resp = my_socket.recv(1024).decode('utf-8')
                        print('\nReceived from ' + server + ':\n' + serv_resp)

                        # log:
                        text = 'Received from 127.0.0.1:' +\
                               self.port_to_log[server] + ':' + serv_resp
                        log(TAGhandler, text)

                        self.wfile.write(bytes(serv_resp, 'utf-8'))
                        print('Resending to ' + client + ' ...')

                        # log:
                        text = 'Sent to ' + self.client_address[0] + ':' +\
                               str(self.client_address[1]) + ': ' + serv_resp
                        log(TAGhandler, text)

                if SerReg is False:
                    print('Invite receiver <' + server +
                          '> is not registered.' + ' Sending 404...')
                    self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')

                    # log:
                    text = 'Sent to ' + self.client_address[0] + ':' +\
                           str(self.client_address[1]) + ': ' +\
                           'SIP/2.0 404 User Not Found\r\n\r\n'
                    log(TAGhandler, text)
                    text = '--------------------------------------------'
                    log(TAGhandler, text)

        if method == 'ACK':

            # log:
            text = 'Received from ' + self.client_address[0] + ':' +\
                   str(self.client_address[1]) + ': ' + rec_data
            log(TAGhandler, text)

            server = rec_data.split(' ')[1][4:]

            my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if server == 'jesse@pinkman.com':
                my_socket.connect((self.Users[server]['address'], 2222))
            if server == 'walter@white.com':
                my_socket.connect((self.Users[server]['address'], 1112))
            print('Resending ACK to ' + server + ' ...')
            my_socket.send(bytes(rec_data, 'utf-8'))

            # log:
            text = 'Sent to 127.0.0.1: ' + self.port_to_log[server] +\
                   ':' + rec_data
            log(TAGhandler, text)
            text = '--------------------------------------------'
            log(TAGhandler, text)

            print('\n----------------------------------------')
            print(rec_data.split(' '))
            print(' ')
            print(self.Users)
            print('----------------------------------------\n')

        if method == 'BYE':

            # log:
            text = 'Received from ' + self.client_address[0] + ':' +\
                   str(self.client_address[1]) + ': ' + rec_data
            log(TAGhandler, text)

            server = rec_data.split(' ')[1][4:]
            SerReg = False
            for user in self.Users:
                if user == server:
                    SerReg = True
                    print('Resending to server... <' + server + '>')
                    my_socket = socket.socket(socket.AF_INET,
                                              socket.SOCK_DGRAM)
                    my_socket.setsockopt(socket.SOL_SOCKET,
                                         socket.SO_REUSEADDR, 1)
                    if server == 'jesse@pinkman.com':
                        my_socket.connect((self.Users[user]['address'],
                                           2222))
                    if server == 'walter@white.com':
                        my_socket.connect((self.Users[user]['address'],
                                           1112))
                    my_socket.send(bytes(rec_data, 'utf-8'))

                    # log:
                    text = 'Sent to 127.0.0.1: ' + self.port_to_log[server] +\
                           ':' + rec_data
                    log(TAGhandler, text)

                    serv_resp = my_socket.recv(1024).decode('utf-8')
                    print('\nReceived from ' + server + ':\n' + serv_resp)

                    # log:
                    text = 'Received from 127.0.0.1:' +\
                           self.port_to_log[server] + ':' + serv_resp
                    log(TAGhandler, text)

                    self.wfile.write(bytes(serv_resp, 'utf-8'))
                    print('Resending to client...')

                    # log:
                    text = 'Sent to ' + self.client_address[0] + ':' +\
                           str(self.client_address[1]) + ': ' + serv_resp
                    log(TAGhandler, text)
                    text = '--------------------------------------------'
                    log(TAGhandler, text)

            if SerReg is False:
                print('Invite receiver <' + server +
                      '> is not registered.' + ' Sending 404...')
                self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')

                # log:
                text = 'Sent to ' + self.client_address[0] + ':' +\
                       str(self.client_address[1]) + ': ' +\
                       'SIP/2.0 404 User Not Found\r\n\r\n'
                log(TAGhandler, text)
                text = '--------------------------------------------'
                log(TAGhandler, text)

        self.register2json()

    def register2json(self):
        '''Update json file'''

        json.dump(self.Users, open(TAGhandler.database, 'w'), indent=4)

    def json2registered(self):
        '''Loader json (users) file'''

        try:
            with open(TAGhandler.database) as fich:
                self.Users = json.load(fich)
        except:
            pass

if __name__ == "__main__":

    try:
        config_file = sys.argv[1]
    except:
        sys.exit('\nUsage: python3 proxy_registrar.py config\n')

    if os.path.isfile(config_file):
        print('\nConfigFile:', config_file, '\n')
    else:
        sys.exit('\n' + '<' + sys.argv[1] + '> File not found.' + '\n')
# -------Error al meter parametros y si no encuentra el fichero hecho----

    parser = make_parser()
    TAGhandler = ProxyParser()
    parser.setContentHandler(TAGhandler)
    parser.parse(open(config_file))

    serv = socketserver.UDPServer((TAGhandler.IPreg, int(TAGhandler.PORTreg)),
                                  ProxyReceivHandler)
    print('\nServer ' + TAGhandler.NAMEreg + ' listening at port ' +
          TAGhandler.PORTreg + '...')

    # log:
    text = 'Starting...'
    log(TAGhandler, text)
    text = 'Server ' + TAGhandler.NAMEreg + ' listening at port ' +\
           TAGhandler.PORTreg + '...'
    log(TAGhandler, text)

    try:
        serv.serve_forever()
    except KeyboardInterrupt:

        # log:
        text = 'Finishing.'
        log(TAGhandler, text)
        text = '--------------------------------------------'
        log(TAGhandler, text)

        print(" ---> Finished Proxy-Registrar Server.")

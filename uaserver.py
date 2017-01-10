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

    def __init__(self):

        self.name = ''
        self.passwd = ''
        self.IPserv = ''
        self.PORTserv = ''
        self.PORTrtp = ''
        self.IPpr = ''
        self.PORTpr = ''
        self.audio = ''

    def startElement(self, name, attrs):

        if name == 'account':
            self.name = attrs.get('username', '')
            self.passwd = attrs.get('passwd', '')
            print('\nUser:           ' + self.name + ' >< ' + self.passwd)
        elif name == 'uaserver':
            self.IPserv = attrs.get('ip', '')
            self.PORTserv = attrs.get('puerto', '')
            print('Serving part:   ' + self.IPserv + ' >< ' + self.PORTserv)
        elif name == 'rtpaudio':
            self.PORTrtp = attrs.get('puerto', '')
        elif name == 'regproxy':
            self.IPpr = attrs.get('ip', '')
            self.PORTpr = attrs.get('puerto', '')
            print('Proxy:          ' + self.IPpr + ' >< ' + self.PORTpr + '\n')
        #  elif name == 'log':
        elif name == 'audio':
            self.audio = attrs.get('path', '')


class ServHandler(socketserver.DatagramRequestHandler):
    '''
    For each petition.
    '''

    rtp_user = []

    def handle(self):

        rec_data = self.rfile.read().decode('utf-8')

        print('Received:\n' + rec_data)

        method = rec_data.split(' ')[0]
        client = rec_data.split(' ')[1]

        Trying = 'SIP/2.0 100 Trying\r\n\r\n'
        Ring = 'SIP/2.0 180 Ring\r\n\r\n'
        OK = 'SIP/2.0 200 OK\r\nContent-Type: application/sdp\r\n\r\n' +\
             'v=0\r\no=' + TAGhandler.name + ' 127.0.0.1\r\ns=session\r\n' +\
             't=0\r\nm=audio ' + TAGhandler.PORTrtp + ' RTP\r\n'

        if method == 'INVITE':
            print('Sending Trying...\n')
            self.wfile.write(bytes(Trying + Ring + OK, 'utf-8'))
            print(rec_data.split(' '))

            rtp_port_to = rec_data.split(' ')[5]
            rtp_name_to = rec_data.split(' ')[3][rec_data.split(' ')[3]
                                                 .rfind('=')+1:]
            self.rtp_user.append(rtp_port_to)
            self.rtp_user.append(rtp_name_to)

        if method == 'ACK':

            aEjecutar = './mp32rtp -i 127.0.0.1 -p ' + self.rtp_user[0] +\
                        ' < ' + TAGhandler.audio
            os.system(aEjecutar)
            print('\nSending ' + TAGhandler.audio + ' --> ' + aEjecutar)

            # Clean rtp list
            print(self.rtp_user)
            self.rtp_user = []

        if method == 'BYE':
            print('Sending OK...\n')
            self.wfile.write(b'SIP/2.0 200 OK\r\n\r\n')
            # acabar rtp-----------------------------------------------------


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

    serv = socketserver.UDPServer((TAGhandler.IPserv,
                                   int(TAGhandler.PORTserv)), ServHandler)

    print('\nListening...\n')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print(" ---> Finished User Agent Server.")

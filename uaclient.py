#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import sys
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import os.path
import os
import hashlib
import time


class UAclient(ContentHandler):
    """
    Class to extract data from xml file (config)
    """

    def __init__(self):

        self.name = ''
        self.passwd = ''
        self.IPserv = ''
        self.PORTserv = ''
        self.IPpr = ''
        self.PORTpr = ''
        self.log = ''

    def startElement(self, name, attrs):

        if name == 'account':
            self.name = attrs.get('username', '')
            self.passwd = attrs.get('passwd', '')
            print('User:           ' + self.name + ' >< ' + self.passwd)
        elif name == 'uaserver':
            self.IPserv = attrs.get('ip', '')
            self.PORTserv = attrs.get('puerto', '')
            print('Serving part:   ' + self.IPserv + ' >< ' + self.PORTserv)
        elif name == 'rtpaudio':
            self.PORTrtp = attrs.get('puerto', '')
        elif name == 'regproxy':
            self.IPpr = attrs.get('ip', '')
            self.PORTpr = attrs.get('puerto', '')
            print('Proxy:          ' + self.IPpr + ' >< ' + self.PORTpr)
        elif name == 'log':
            self.log = attrs.get('path', '')
            print('Log file:       ' + self.log)
        elif name == 'audio':
            self.audio = attrs.get('path', '')
            print('Audio file:     ' + self.audio)


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


if __name__ == "__main__":

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

    # XML data searcher
    parser = make_parser()
    TAGhandler = UAclient()
    parser.setContentHandler(TAGhandler)
    parser.parse(open(config_file))

    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((TAGhandler.IPpr, int(TAGhandler.PORTpr)))
    try:
        if method == 'register':

            # log:
            text = 'Starting...'
            log(TAGhandler, text)

            data = method.upper() + ' sip:' + TAGhandler.name + ':' \
                + TAGhandler.PORTserv + ' SIP/2.0\r\n' + 'Expires: ' \
                + str(option) + '\r\n\r\n'

            # log:
            text = 'Sent to ' + TAGhandler.IPpr + ':' + TAGhandler.PORTpr +\
                ': ' + data
            log(TAGhandler, text)

            print('\n' + "Sending:\n" + data)
            my_socket.send(bytes(data, 'utf-8'))

            rec_data = my_socket.recv(1024).decode('utf-8')

            print('Received:\n' + rec_data)

            # log:
            text = 'Received from ' + TAGhandler.IPpr + ':' +\
                TAGhandler.PORTpr + ': ' + rec_data
            log(TAGhandler, text)

            if rec_data.split(' ')[1] == '401':

                nonce = rec_data.split('"')[1]
                # We create a response:
                m = hashlib.sha1()
                m.update(bytes(TAGhandler.passwd, 'utf-8'))
                m.update(bytes(nonce, 'utf-8'))
                response = m.hexdigest()

                aut_data = method.upper() + ' sip:' + TAGhandler.name + ':' \
                    + TAGhandler.PORTserv + ' SIP/2.0\r\n' + 'Expires: ' \
                    + str(option) + '\r\n' + 'Authorization: ' + \
                    str(response) + '\r\n\r\n'
                print('Sending authentication:\n' + aut_data)
                my_socket.send(bytes(aut_data, 'utf-8'))

                # log:
                text = 'Sent to ' + TAGhandler.IPpr + ':' +\
                       TAGhandler.PORTpr + ': ' + aut_data
                log(TAGhandler, text)

                rec_data = my_socket.recv(1024).decode('utf-8')
                print('Received:\n' + rec_data)

                # log:
                text = 'Received from ' + TAGhandler.IPpr + ':' +\
                       TAGhandler.PORTpr + ': ' + rec_data
                log(TAGhandler, text)

            # log:
            text = '--------------------------------------------'
            log(TAGhandler, text)

        if method == 'invite':

            body = 'v=0\r\no=' + TAGhandler.name +\
                   ' 127.0.0.1\r\ns=session\r\n' + 't=0\r\nm=audio ' +\
                   TAGhandler.PORTrtp + ' RTP\r\n'
            data = method.upper() + ' sip:' + option + ' SIP/2.0\r\n' +\
                'Content-Type: application/sdp\r\n\r\n' + body

            print('\n' + "Sending:\n" + data)
            my_socket.send(bytes(data, 'utf-8'))

            # log:
            text = 'Sent to ' + TAGhandler.IPpr + ':' +\
                   TAGhandler.PORTpr + ': ' + data
            log(TAGhandler, text)

            rec_data = my_socket.recv(1024).decode('utf-8')
            print('Received:\n' + rec_data)

            # log:
            text = 'Received from ' + TAGhandler.IPpr + ':' +\
                   TAGhandler.PORTpr + ': ' + rec_data
            log(TAGhandler, text)

            if rec_data.split(' ')[1] == '100':
                print('Sending ACK...')
                my_socket.send(bytes('ACK sip:' + option + ' SIP/2.0\r\n\r\n',
                                     'utf-8'))

                # log:
                text = 'Sent to ' + TAGhandler.IPpr + ':' +\
                       TAGhandler.PORTpr + ': ' + 'ACK sip:' + option +\
                       ' SIP/2.0\r\n\r\n'
                log(TAGhandler, text)

                rtp_to = rec_data.split(' ')[9]

                aEjecutar = './mp32rtp -i 127.0.0.1 -p ' + rtp_to + ' < ' +\
                    TAGhandler.audio
                os.system(aEjecutar)
                print('\nSending ' + rtp_to + ' --> ' + aEjecutar + '\n')

                # log:
                text = 'Sending to 127.0.0.1:' + rtp_to + ' audio file <' +\
                       TAGhandler.audio + '>'
                log(TAGhandler, text)
                text = '--------------------------------------------'
                log(TAGhandler, text)

        if method == 'bye':
            data = method.upper() + ' sip:' + option + ' SIP/2.0\r\n\r\n'
            print('\n' + "Sending:\n" + data)
            my_socket.send(bytes(data, 'utf-8'))

            # log:
            text = 'Sent to ' + TAGhandler.IPpr + ':' + TAGhandler.PORTpr +\
                   ': ' + data
            log(TAGhandler, text)

            rec_data = my_socket.recv(1024).decode('utf-8')
            print('Received:\n' + rec_data)

            # log:
            text = 'Received from ' + TAGhandler.IPpr + ':' +\
                   TAGhandler.PORTpr + ': ' + rec_data
            log(TAGhandler, text)
            text = '--------------------------------------------'
            log(TAGhandler, text)
            text = 'Finishing.'
            log(TAGhandler, text)
            text = '--------------------------------------------'
            log(TAGhandler, text)

        print('Finished socket.\n')
        my_socket.close()
    except:
        text = 'Error: 20101018160243 Error: No server listening at ' +\
                   '127.0.0.1 port 20000'
        log(TAGhandler, text)
        text = '--------------------------------------------'
        log(TAGhandler, text)

        sys.exit('20101018160243 Error: No server listening at ' +
                 '127.0.0.1 port 20000')

#!/usr/bin/env python

from __future__ import print_function
import pcap
import re
import urllib2
import os
import time
import zlib
import json
import socket

chown_command = ''
playlist = []
invalid = ['/', '\\', ':', '*', '?', '"', "'", '<', '>', '|']


def valid_filename(s):
    return filter(lambda x: x not in invalid, s)


class IP:
    def __init__(self, data):
        if len(data) != 4:
            raise Exception(
                'IP must exactly 4 bytes, not {0}'.format(len(data)))
        self._data = data

    def __str__(self):
        return '.'.join('{0}'.format(ord(c)) for c in self._data)

    def __eq__(self, other):
        return self._data == other._data


class Port:
    def __init__(self, data):
        if len(data) != 2:
            raise Exception(
                'Port must exactly 2 bytes, not {0}'.format(len(data)))
        self._data = data

    def __str__(self):
        return '{0}'.format(self.value())

    def value(self):
        return ord(self._data[0]) * 256 + ord(self._data[1])


class TCPParser:
    def __init__(self, data):
        self.is_valid = False
        if len(data) < 44:
            self.is_valid = False
        else:
            self._data = data
            self.parse()

    def __bool__(self):
        return self.is_valid

    def parse(self):
        if ord(self._data[23]) != 6:
            self.is_valid = False
            return
        self.src = IP(self._data[26:30])
        self.dst = IP(self._data[30:34])
        self.src_port = Port(self._data[34:36])
        self.dst_port = Port(self._data[36:38])
        self.flags = (ord(self._data[46]) % 16) * 256 + ord(self._data[47])
        self.tcp_header_len = 4 * (ord(self._data[46]) >> 4)
        self.tcp_header = self._data[34:34 + self.tcp_header_len]
        self.tcp_data = self._data[34 + self.tcp_header_len:]
        self.is_valid = True

    def flag_push(self):
        return self.flags & (1 << 3) > 0

    def flag_ack(self):
        return self.flags & (1 << 4) > 0

TCPParser.__nonzero__ = TCPParser.__bool__


class HttpParser:
    def __init__(self, data):
        self._data = data
        self.parse()

    def parse(self):
        m = re.match('(?s)(.*\x0d\x0a\x0d\x0a)(.*)', self._data)
        if m:
            self.head = m.group(1)
            self.body = m.group(2)
        else:
            self.head = ''
            self.body = ''


class HttpSegment:
    def __init__(self, request_pattern, process):
        self._data = ''
        self._pattern = re.compile(request_pattern)
        self._server_ip = None
        self._process = process
        self.head = ''

    def check_package(self, data):
        tcp = TCPParser(data)
        if not tcp or len(tcp.tcp_data) == 0:
            return False
        # save ip of remote server if the send package match self._pattern
        if not self._server_ip and tcp.dst_port.value() == 80 \
                and self._pattern.search(data):
            self._server_ip = tcp.dst
            self._new_segment = True
        # if server ip is set, copy received data to self._buffer
        if self._server_ip and self._server_ip._data == tcp.src._data:
            #if not the first package, save all tcp data
            if not self._new_segment:
                self._buffer += tcp.tcp_data
            #if it's the first package, it has HTTP header
            else:
                http = HttpParser(tcp.tcp_data)
                if len(http.body) < 100:
                    return False
                self.head = http.head
                self._buffer = http.body
                self._new_segment = False
            # a PSH flag in TCP package indicate end of a TCP segment
            if not tcp.flag_push():
                return True
            if self._process:
                self._process(self.head, self._buffer)
            self._server_ip = None
            return True
        return False


def download(url, file_name=None):
    path_name = 'songs/'
    if not os.path.exists(os.path.relpath(path_name)):
        os.mkdir(path_name)
        os.system(chown_command.format(path_name))
    file_name = path_name + file_name if file_name else url.split('/')[-1]
    if (os.path.exists(file_name)):
        print('File {0} exists, ignore downloading'.format(file_name))
        return
    print('Downloading {0} to {1}'.format(url, file_name))
    req = urllib2.Request(url)
    # make the server treat us as a web browser
    req.add_header('User-Agent',
                   'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
    u = urllib2.urlopen(req, timeout=10)
    f = open(file_name, 'wb')
    meta = u.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            print('Download {0} Completed'.format(file_name))
            break
        file_size_dl += len(buffer)
        f.write(buffer)
        status = r"%10d  [%3.2f%%]" % (
            file_size_dl, file_size_dl * 100. / file_size)
        status = status + chr(8) * (len(status) + 1)
        print(status, end='')
    f.close()
    # change file owner
    os.system(chown_command.format('"' + file_name + '"'))


def process_playlist(head, body):
    if len(body) < 100:
        return
    global playlist
    ret = json.loads(zlib.decompress(body, 16 + zlib.MAX_WBITS))
    playlist.extend(ret['song'])


seg_playlist = HttpSegment('j/mine/playlist\?type=[nps]', process_playlist)


def my_handler(ts, package):
    if seg_playlist.check_package(package):
        return
    tcp = TCPParser(package)
    if tcp and tcp.tcp_data > 100:
        m = re.search(r'GET .*/view/song/small/(.*\.mp3) HTTP', tcp.tcp_data)
        if not m:
            return
        # search url in the playlist
        try:
            info = next(x for x in playlist if m.group(1) in x['url'])
        except StopIteration:
            return
        file_name = valid_filename('-'.join([info['artist'],
                                             info['title']]) + ".mp3")
        try:
            time.sleep(3)
            download(info['url'], file_name.encode('utf-8'))
        except urllib2.HTTPError:
            print('urllib2.HTTPError')
        except socket.timeout:
            print('socket.timeout')


def make_chown_command():
    # see http://stackoverflow.com/a/6447942/1032255
    username = os.getenv('SUDO_USER')
    global chown_command
    if username:
        chown_command = 'chown {0}:{1} {2}'.format(username, username, '{0}')
    else:
        chown_command = ''


if __name__ == "__main__":
    try:
        pc = pcap.pcap()
    except:
        print('This script must run as root')
        exit()
    make_chown_command()
    pc.setfilter('tcp && (src port 80 || dst port 80)')
    print('Listening on %s: %s' % (pc.name, pc.filter))
    pc.loop(0, my_handler)

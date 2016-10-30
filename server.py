#!/usr/bin/python3
#    DOSpot: A joke low-interaction SSH honeypot that mimics an MS-DOS system.
#    Copyright © 2016  RunasSudo (Yingtong Li)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version, with the additional permission that,
#    notwithstanding anything to the contrary, this program, or a modified version
#    thereof, need not divulge any information about its nature or licensing to
#    any users interacting with it remotely through a computer network, provided
#    that you make available the source code upon request or redistribution in
#    compliance with sections 4, 5 and 6 of the licence.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import dos

import paramiko

import threading
import socket

host_key = paramiko.RSAKey(filename='server_rsa.key')

root_passwords = [('oracle', 'oracle'), ('root', 'root'), ('root', 'abc123'), ('root', 'password'), ('root', '123456'), ('root', 'admin'), ('test', 'test'), ('root', '123qwe'), ('test', 'password'), ('admin', 'admin')]

class Server(paramiko.ServerInterface):
	def __init__(self):
		self.event = threading.Event()
	
	def check_channel_request(self, kind, chanid):
		if kind == 'session':
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
	
	def check_auth_password(self, username, password):
		if (username, password) in root_passwords:
			return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED
	
	def get_allowed_auths(self, username):
		return 'password'
	
	def check_channel_shell_request(self, channel):
		self.event.set()
		return True
	
	def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
		return True

# Start server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', 2200))
sock.listen(100)

while True:
	print('Waiting for client')
	client, addr = sock.accept()
	print('Got a client!')
	try:
		t = paramiko.Transport(client)
		t.add_server_key(host_key)
		server = Server()
		t.start_server(server=server)
		
		chan = t.accept(20)
		if chan is None:
			print('No channel')
			continue
		print('Authenticated!')
		
		server.event.wait(10)
		if not server.event.is_set():
			print('Client never asked for a shell')
			continue
		print('Connecting to DOSpot!')
		
		fin = chan.makefile('r')
		fout = chan.makefile('w')
		
		dospot = dos.DOSpot(fin, fout)
		#dospot.start()
		dospot.run()
	except Exception as ex:
		import traceback; traceback.print_exc()
		client.close()

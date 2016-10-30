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

import threading

class DOSpot(threading.Thread):
	def __init__(self, fin, fout, islocal=False):
		super().__init__(daemon=True)
		
		self.fin = fin
		self.fout = fout
		self.islocal = islocal
		
		self.currdrv = 'C'
		self.currdir = []
		
		self.roottree = {
			'DOS': {},
			'AUTOEXEC.BAT': 97,
			'COMMAND.COM': 37557,
			'CONFIG.SYS': 68,
			#'IO.SYS': 33337,
			#'MSDOS.SYS': 37376
		}
		
		self.c_echo = True
	
	def print(self, *args, **kwargs):
		if not self.islocal:
			kwargs['end'] = kwargs['end'] if 'end' in kwargs else '\r\n'
		return print(*args, **kwargs, file=self.fout)
	
	def input(self, prompt):
		self.print(prompt, end='')
		self.fout.flush()
		
		if self.islocal:
			return self.fin.readline().rstrip('\n')
		else:
			buf = ''
			while True:
				char = self.fin.read(1).decode('ascii')
				byte = ord(char)
				#print(byte)
				if char == '\r': # enter
					self.print()
					break
				elif byte == 0x7F: # backspace
					if len(buf) > 0:
						self.print('\b \b', end='') # dodgy af
						buf = buf[:-1]
				elif byte >= 0x00 and byte <= 0x1F: # ASCII control
					hr = '^' + chr(byte + 64)
					self.print(hr, end='')
					buf += hr
				elif byte >= 0x20 and byte <= 0x7E: # printable
					self.print(char, end='')
					buf += char
			return buf
	
	def run(self):
		self.print('MS-DOS Version 4.01')
		
		def pwd(drv=self.currdrv, dir_=self.currdir):
			return '{}:\\{}'.format(drv, '\\'.join(dir_))
		
		def traverse(path, tree=self.roottree):
			if len(path) == 0:
				return tree
			if path[0] in tree:
				return traverse(path[1:], tree[path[0]])
			return False
		
		while True:
			s = self.input('{}>'.format(pwd()) if self.c_echo else '').strip()
			
			if len(s) > 0:
				args = s.split()
				cmd = args[0].lower()
				
				if cmd == 'echo' or s.startswith('echo.'):
					arg = s[5:]
					if arg.lower() == 'on':
						self.c_echo = True
					elif arg.lower() == 'off':
						self.c_echo = False
					elif len(arg) > 0 or s.startswith('echo.'):
						self.print(arg)
					else:
						self.print('ECHO is {}'.format('on' if self.c_echo else 'off'))
				elif cmd == 'dir':
					dir_ = self.currdir + ([] if len(args) == 1 else [args[1]])
					
					self.print()
					self.print(' Volume in drive {} is ROOTDISK'.format(self.currdrv))
					self.print(' Volume Serial Number is 2958-0B1B')
					self.print(' Directory of  {}'.format(pwd(self.currdrv, dir_)))
					self.print()
					
					num = 0
					if len(dir_) > 0:
						self.print('{:<8}     <DIR>     04-07-89  12:00a'.format('.'))
						self.print('{:<8}     <DIR>     04-07-89  12:00a'.format('..'))
						num += 2
					for item, value in traverse(dir_).items():
						if type(value) == dict:
							self.print('{:<8}     <DIR>     04-07-89  12:00a'.format(item))
						else:
							self.print('{:<8} {:<3} {:>9} 04-07-89  12:00a'.format(*item.split('.'), value))
						num += 1
					
					self.print('{:>9} File(s) {:>10} bytes free'.format(num, '31141889'))
				elif cmd == 'del':
					target = traverse(self.currdir + [args[1]])
					if target is not False:
						if type(target) == dict:
							self.print('All files in directory will be deleted!')
							resp = self.input('Are you sure (Y/N)?').strip()
							if resp.lower() == 'y':
								self.print('Access denied')
						else:
							self.print('Access denied')
					else:
						self.print('File not found')
				elif cmd == 'ver':
					self.print()
					self.print('MS-DOS Version 4.01')
				else:
					self.print('Bad command or file name')
				
				if self.c_echo:
					self.print()

if __name__ == '__main__':
	import sys
	dospot = DOSpot(sys.stdin, sys.stdout, True)
	dospot.run()

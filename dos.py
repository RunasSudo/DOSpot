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

class DOSException(Exception):
	def __init__(self, message):
		self.message = message
		super().__init__(message)

class DOSpot(threading.Thread):
	def __init__(self, fin, fout, client):
		super().__init__(daemon=True)
		
		self.fin = fin
		self.fout = fout
		self.client = client
		
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
		if self.client is not None:
			kwargs['end'] = kwargs['end'] if 'end' in kwargs else '\r\n'
		return print(*args, **kwargs, file=self.fout)
	
	def input(self, prompt):
		self.print(prompt, end='')
		self.fout.flush()
		
		if self.client is None:
			try:
				return self.fin.readline().rstrip('\n')
			except KeyboardInterrupt as ex:
				self.running = False
				return ''
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
			return '{}:\\{}'.format(drv, '\\'.join(dir_)).upper()
		
		def checkpath(path, tree=self.roottree):
			if len(path) == 0:
				return tree
			if type(tree) != dict:
				raise DOSException('Access denied')
			if path[0].upper() in tree:
				return checkpath(path[1:], tree[path[0].upper()])
			if len(path) > 1:
				raise DOSException('Path not found')
			raise DOSException('File not found')
		
		def traverse(path, tree=self.roottree):
			try:
				return checkpath(path, tree)
			except DOSException as ex:
				return False
		
		def resolvepath(path):
			dir_ = []
			
			if len(path[0]) == 2 and path[0][1] == ':':
				# absolute path
				if path[0][0] == self.currdrv:
					path = path[1:]
				else:
					raise DOSException('Invalid drive specification')
			else:
				# relative path
				dir_.extend(self.currdir)
			
			for bit in path:
				if bit == '.':
					pass
				elif bit == '..':
					if len(dir_) > 0:
						dir_.pop()
					else:
						raise DOSException('Invalid directory')
				else:
					dir_.append(bit)
			
			return dir_
		
		
		def cmd_attrib(s, args, cmd):
			path = None
			flags = []
			for arg in args[1:]:
				if arg.startswith('+') or arg.startswith('-'):
					flags.append(arg)
				elif path is None:
					path = arg
				else:
					raise DOSException('Invalid parameter - {}'.format(arg.upper()))
			if path is None:
				raise DOSException('Required parameter missing')
			
			try:
				target = checkpath(resolvepath(path.split('\\')))
			except DOSException as ex:
				raise DOSException('{} - {}'.format(ex.message, path.upper()))
			
			if type(target) == dict:
				raise DOSException('File not found - {}'.format(path.upper()))
			elif len(flags) == 0:
				self.print('  A    R     {}'.format(pwd(self.currdrv, resolvepath(path.split('\\')))))
			else:
				raise DOSException('Access denied - {}'.format(path.upper()))
		
		def cmd_cd(s, args, cmd):
			dir_ = resolvepath(args[1].split('\\'))
			checkpath(dir_)
			currdir = dir_
		
		def cmd_command(s, args, cmd):
			pass
		
		def cmd_copy(s, args, cmd):
			if len(args) == 1:
				raise DOSException('Required parameter missing')
			
			try:
				source = checkpath(resolvepath(args[1].split('\\')))
			except DOSException as ex:
				raise DOSException('{} - {}\r\n        0 File(s) copied'.format(ex.message, args[1].upper()))
			
			if len(args) > 2:
				dir_ = args[2].split('\\')
				destname = args[2]
			else:
				dir_ = self.currdir + [args[1].split('\\')[-1]]
				destname = args[1].split('\\')[-1]
			
			try:
				dest = checkpath(resolvepath(dir_))
			except DOSException as ex:
				if ex.message == 'File not found':
					# copy the file
					raise DOSException('Access denied - {}\r\n        0 File(s) copied'.format(destname.upper()))
				raise DOSException('{} - {}\n        0 File(s) copied'.format(ex.message, args[2].upper()))
			# overwrite the file
			raise DOSException('Access denied - {}\r\n        0 File(s) copied'.format(destname.upper()))
		
		def cmd_del(s, args, cmd):
			dir_ = resolvepath(args[1].split('\\'))
			checkpath(dir_)
			
			target = traverse(dir_)
			if type(target) == dict:
				self.print('All files in directory will be deleted!')
				resp = self.input('Are you sure (Y/N)?').strip()
				if resp.lower() == 'y':
					raise DOSException('Access denied')
			else:
				raise DOSException('Access denied')
		
		def cmd_dir(s, args, cmd):
			if len(args) > 2:
				raise DOSException('Too many parameters - {}'.format(args[2]))
			
			try:
				dir_ = resolvepath(args[1].split('\\')) if len(args) > 1 else self.currdir
			except DOSException as ex:
				if ex.message == 'Invalid directory':
					self.print()
					self.print(' Volume in drive {} is ROOTDISK'.format(self.currdrv))
					self.print(' Volume Serial Number is 2958-0B1B')
					self.print(' Directory of  {}'.format(pwd(self.currdrv, self.currdir)))
					self.print()
					raise ex
				else:
					raise ex
			
			self.print()
			self.print(' Volume in drive {} is ROOTDISK'.format(self.currdrv))
			self.print(' Volume Serial Number is 2958-0B1B')
			
			if traverse(dir_) is False:
				try:
					checkpath(dir_)
				except DOSException as ex:
					if ex.message == 'File not found':
						self.print(' Directory of  {}'.format(pwd(self.currdrv, dir_[:-1])))
						self.print()
						raise ex
					else:
						raise ex
			elif type(traverse(dir_)) == dict:
				self.print(' Directory of  {}'.format(pwd(self.currdrv, dir_)))
				self.print()
				
				num = 0
				if len(dir_) > 0:
					self.print('{:<8}     <DIR>     04-07-89  12:00a'.format('.'))
					self.print('{:<8}     <DIR>     04-07-89  12:00a'.format('..'))
					num += 2
				for item, value in sorted(sorted(traverse(dir_).items(), key=lambda x: x[0]), key=lambda x: type(x[1]) == dict):
					if type(value) == dict:
						self.print('{:<8}     <DIR>     04-07-89  12:00a'.format(item))
					else:
						self.print('{:<8} {:<3} {:>9} 04-07-89  12:00a'.format(*item.split('.'), value))
					num += 1
				
				self.print('{:>9} File(s) {:>10} bytes free'.format(num, '31141889'))
			else:
				self.print(' Directory of  {}'.format(pwd(self.currdrv, dir_[:-1])))
				self.print()
				if type(traverse(dir_)) == dict:
					self.print('{:<8}     <DIR>     04-07-89  12:00a'.format(dir_[-1].upper()))
				else:
					self.print('{:<8} {:<3} {:>9} 04-07-89  12:00a'.format(*dir_[-1].upper().split('.'), traverse(dir_)))
				self.print('{:>9} File(s) {:>10} bytes free'.format(1, '31141889'))
		
		def cmd_echo(s, args, cmd):
			arg = s[5:]
			if arg.lower() == 'on':
				self.c_echo = True
				return
			if arg.lower() == 'off':
				self.c_echo = False
				return
			if len(arg) > 0 or s.startswith('echo.'):
				self.print(arg)
				return
			self.print('ECHO is {}'.format('on' if self.c_echo else 'off'))
		
		def cmd_exit(s, args, cmd):
			self.running = False
		
		def cmd_help(s, args, cmd):
			self.print("""ATTRIB   Displays or changes file attributes.
CD       Displays the name of or changes the current directory.
COMMAND  Starts a new instance of the MS-DOS command interpreter.
COPY     Copies one or more files to another location.
DEL      Deletes one or more files.
DIR      Displays a list of files and subdirectories in a directory.
ECHO     Displays messages, or turns command echoing on or off.
ERASE    Deletes one or more files.
EXIT     Quits the COMMAND.COM program (command interpreter).
HELP     Provides Help information for MS-DOS commands.
MD       Creates a directory.
MKDIR    Creates a directory.
RD       Removes a directory.
RMDIR    Removes a directory.
VER      Displays the MS-DOS version.""")
		
		def cmd_mkdir(s, args, cmd):
			dir_ = resolvepath(args[1].split('\\'))
			try:
				target = checkpath(dir_)
			except DOSException as ex:
				if ex.message == 'File not found':
					# create the directory
					raise DOSException('Unable to create directory')
				else:
					raise ex
			
			if type(target) == dict:
				raise DOSException('Directory already exists')
			else:
				raise DOSException('Unable to create directory')
		
		def cmd_rmdir(s, args, cmd):
			dir_ = resolvepath(args[1].split('\\'))
			
			raise DOSException('Invalid path, not directory,\r\nor directory not empty.')
		
		def cmd_ver(s, args, cmd):
			self.print()
			self.print('MS-DOS Version 4.01')
		
		
		shl_cmds = {'cd': cmd_cd, 'copy': cmd_copy, 'del': cmd_del, 'dir': cmd_dir, 'echo': cmd_echo, 'erase': cmd_del, 'exit': cmd_exit, 'help': cmd_help, 'md': cmd_mkdir, 'mkdir': cmd_mkdir, 'rd': cmd_rmdir, 'rmdir': cmd_rmdir, 'ver': cmd_ver}
		ext_cmds = {'attrib': cmd_attrib, 'command': cmd_command}
		
		self.running = True
		while self.running:
			s = self.input('{}>'.format(pwd()) if self.c_echo else '').strip()
			
			if len(s) > 0:
				args = s.split()
				cmd = args[0].lower()
				
				try:
					if cmd in shl_cmds:
						shl_cmds[cmd](s, args, cmd)
					elif cmd in ext_cmds:
						ext_cmds[cmd](s, args, cmd)
					elif '.' in args[0] and args[0][:args[0].index('.')] in shl_cmds:
							cmd = args[0][:args[0].index('.')]
							args = [cmd] + s[len(cmd):].split()
							shl_cmds[cmd](s, args, cmd)
					else:
						self.print('Bad command or file name')
				except DOSException as ex:
					self.print(ex)
				
				if self.c_echo:
					self.print()
		
		if self.client is not None:
			self.client.close()

if __name__ == '__main__':
	import sys
	dospot = DOSpot(sys.stdin, sys.stdout, None)
	dospot.run()

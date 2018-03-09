from PyQt5.QtCore import QThread, pyqtSlot, pyqtSignal, Qt
from PyQt5.QtNetwork import QUdpSocket, QHostAddress
import queue
import threading
import time
import paramiko
import socket
from queue import Queue



class SshClientWorker(QThread):
	""" thread to handle ssh connection
	"""

	finished_connecting_to_server = pyqtSignal(bool, 'QString')
	finished_executing_cmd = pyqtSignal(bool, 'QString', 'QString', 'QString')
	finished_closing_ssh_connection = pyqtSignal()

	def __init__(self):

		super(SshClientWorker, self).__init__()
		# keep commands in a queue
		self.__cmds_q = Queue()


	def run(self):
		""" create and initialize a different thread context
		"""

		self.__ssh_client = paramiko.SSHClient()
		# initialize client parameters
		self.__ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		self.exec()


	@pyqtSlot('QString', int, 'QString', 'QString')
	def start_connecting_to_server(self, host, port, user, pwd):
		""" connect to a server
		"""

		try:
			self.__ssh_client.connect(hostname=host, port=port,\
				username=user, password=pwd)

			self.finished_connecting_to_server.emit(True, 'connected')

		except paramiko.AuthenticationException:
			self.finished_connecting_to_server.emit(False, 'Authentication error')

		except paramiko.SSHException as e1:
			self.finished_connecting_to_server.emit(False, e1.__str__())

		except socket.error as e2:
			self.finished_connecting_to_server.emit(False, e2.__str__())


	@pyqtSlot('QString')
	def start_executing_cmd(self, cmd):
		""" execute a command on the server
		"""
		try:
			# execute
			ssh_stdin, ssh_stdout, ssh_stderr = self.__ssh_client.exec_command(cmd)
			self.finished_executing_cmd.emit(True, cmd, ssh_stdout.read(), ssh_stderr.read())

		except paramiko.SSHException as e:
			# command exceution failed
			self.finished_executing_cmd.emit(False,'', e.__str__())


	@pyqtSlot()
	def start_closing_ssh_connection(self):

		self.__ssh_client.close()
		self.finished_closing_ssh_connection.emit()



class UdpServerWorker(QThread):
	""" Create a worker to handle snort message reception and processing
	"""

	finished_processing_msg = pyqtSignal(dict)

	def __init__(self):

		super(UdpServerWorker, self).__init__()

		# create a queue
		self.__msg_q = queue.Queue()

	def run(self):
		""" create and init a socket and enter into an event loop
		"""
		# udp server socket
		self.__socket = QUdpSocket()
		
		# bind socket to all interfaces and port 4000
		self.__socket.bind(QHostAddress.Any, 4000)
		self.__socket.readyRead.connect(self.read_msg, Qt.DirectConnection)

		# start another worker to process messages
		self.__proc_worker = threading.Thread(target=self.process_msgs)
		self.__proc_worker.setDaemon(True)
		self.__proc_worker.start()

		self.exec()


	def process_msgs(self):
		""" process a snort message
		"""

		while True:
			# get snort messages from the queue, one by one
			msg = self.parse_msg(self.__msg_q.get())
			
			# emit signal
			self.finished_processing_msg.emit(msg)


	def parse_msg(self, msg):
		""" parse msg string, create a dictionary
		"""

		pos, tmp = 0, 0
		pos = msg.find('[')
		tmp = pos
		msg = msg[tmp:]
		pos = msg.find(']')

		sev_fc = (msg[:pos]).strip('[]').split(':')
		pos = pos + 1
		tmp = pos
		msg = msg[tmp:]
		pos = msg.find('{')

		msg_str = msg[:pos]
		msg_str = msg_str.strip(' ')
		is_threat, msg_desc = self.parse_alert(msg_str)
		tmp = pos + 1
		msg = msg[tmp:]
		pos = msg.find('}')
		proto = msg[:pos]

		tmp = pos + 1
		msg = msg[tmp:]

		ips = msg.split('->')

		#dttm, src_addr, dst_addr, src_prt, dst_prt, proto, fc, sv, msg, is_threat
		procssd_msg =  {'time':time.asctime(), 'src': ips[0], 'dest': ips[1], 'proto': proto, \
						'facility':sev_fc[0],  'severity': sev_fc[2], 'msg': msg_desc[0], 'is_threat': is_threat}
		procssd_msg['desc'] = self.desc(procssd_msg)

		return procssd_msg


	def parse_alert(self, err):
		""" parse an error message
		"""
		if 'Classification' not in err:
			return (False, {0:err})

		# Reset outside window [Classification: Potentially Bad Traffic] [Priority: 2]
		pos = err.find('[')
		msg_str = err[:pos].strip(' ')
		err = err[pos:]
		pos = err.find(']') + 1
		clf = err[:pos].strip('[ ]')
		err = err[pos + 1:].strip('[ ]')
		prty = err.split(':')
		clf = clf.split(':')

		return (True, {0:msg_str, 1:clf[1], 2:prty[1]})


	def desc(self, msg):
		""" get a string representation of the snort message
		"""
		return '[ ' + msg['src'] + ' => ' + msg['dest'] + ' ] [ ' + \
				msg['proto'] + ' ] [ ' + msg['msg'] + ' ] [ ' + ('THREAT' if(msg['is_threat']) else 'NOT_THREAT') + ' ]'


	@pyqtSlot()
	def read_msg(self):
		""" read a datagram / message from the socket
		"""
		
		data = self.__socket.receiveDatagram().data().data().decode('ascii')
		# add to queue
		self.__msg_q.put(data)


	@pyqtSlot()
	def close_socket(self):
		""" Close the socket incase the thread exits
		"""
		self.__socket.close()

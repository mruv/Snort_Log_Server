
from PyQt5.QtCore import pyqtSlot, QObject, pyqtSignal
from PyQt5.QtWidgets import QTableWidgetItem, QDialog
import queue
import time
import threading
import paramiko

#import logging
#logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
#from scapy.layers.l2 import ARP, Ether
#from scapy.sendrecv import srp

#conf.verb = 0

###########################################################
## Snort Message --> a Dictionary
###########################################################
class Message(dict):

	def __init__(self, dttm, src, dst, proto, fc, sv, msg, is_threat):
		"""
		constructor
		"""
		super(Message, self).__init__()
		self[0]  = dttm
		self[1]  = src
		self[2]  = dst
		self[3]  = proto
		self[4]  = fc
		self[5]  = sv
		self[6]  = 'YES' if(is_threat) else 'NO'
		self[7]  = msg

	def __str__(self):
		return '< ' + self[0] + ' | ' + self[1] + ' => ' + self[2] +' | ' + self[3] + ' | Fac:' + self[4] + \
				' | Sev:' + self[5] + ' | ' + ('THREAT' if(self[6] == 'YES') else 'NOT_THREAT') + ' | ' + self[7] + ' >'

	def isThreat(self):
		return True if(self[6] == 'YES') else False


###############################################################
## Message description, Can't use dict directly as the type to
## be passed to slot MessageView.updateMsgView()
###############################################################
class Desc(dict):
	def __init__(self, data):
		"""
		constructor
		"""
		super(Desc, self).__init__(data)


###############################################################
## Server utilities
###############################################################
class LogUtils:

	__in_q  = queue.Queue()

	@staticmethod
	@pyqtSlot('QString')
	def addToInQueue(msg):
		LogUtils.__in_q.put(msg)

	@staticmethod
	def getFromInQueue():
		return LogUtils.__in_q.get()

	@staticmethod
	def parseMsg(msg):
		
		#parse msg string, create a Message object
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
		tmp = pos + 1
		msg = msg[tmp:]
		pos = msg.find('}')
		proto = msg[:pos]

		tmp = pos + 1
		msg = msg[tmp:]

		ips = msg.split('->')

		#dttm, src_addr, dst_addr, src_prt, dst_prt, proto, fc, sv, msg, is_threat
		return Message(time.asctime(), ips[0], ips[1], proto, sev_fc[0], sev_fc[2], msg_str, True)

	@staticmethod
	def parseErrorMsg(err):
		pass


###################################################################
## Network Node
###################################################################
class Host(dict):

	def __init__(self, ip = '', mac = '******', os = '******', name = '******', usrs = []):
		"""
		constructor
		"""
		super(Host, self).__init__()
		self[0] = QTableWidgetItem(ip)
		self[1] = QTableWidgetItem(mac)
		self[2] = QTableWidgetItem(name)
		self[3] = QTableWidgetItem(os)
		self[4] = QTableWidgetItem('[ ***, ]')
		self[5] = QTableWidgetItem('1')

	#overload operator
	def __eq__(self, host):
		"""
		if self.__mac.text() == 'Unknown':
			return host.ip().text() == self.__ip.text()
		else:
			return host.mac().text() == self.__mac.text
		"""
		return (host[0].text() == self[0].text())


###################################################################
## Hostile Network Nodes
###################################################################
class HostileHosts(QObject):

	#signals
	newHostileHost_HH        = pyqtSignal(Host)
	newHostileMsgFromHost_HH = pyqtSignal('QString')
	def __init__(self):
		#a list of all hostile hosts
		super(HostileHosts, self).__init__()
		self.__all_hostile_hosts   = []
		#a queue of all hostile messages
		self.__hostile_q           = queue.Queue()

		#connections
		self.newHostileMsgFromHost_HH.connect(self.incr)
		#start a worker thread to do the processing
		wrkr = threading.Thread(target=self.resolver)
		wrkr.setDaemon(True)
		wrkr.start()

	def resolver(self):
		while True:
			try:
				src = self.__hostile_q.get()
				ip = src[:src.rfind(':')]
				# get mac address
				#mac = Host.getMac(ip)
				#if mac == None:
				#	mac = 'Unknown'
				#print(ip)

				h = Host(ip=ip)
				if self.exists(h):
					self.newHostileMsgFromHost_HH.emit(ip)
					#print('Exists')
				else:
					self.newHostileHost_HH.emit(h)
					self.__all_hostile_hosts.append(h)
					#print('Does not exist')
			except:
				continue
				
	# utility methods
	@pyqtSlot('QString')
	def addToHostileQueue_HH(self, src):
		self.__hostile_q.put(src)

	def exists(self, h):
		return (h in self.__all_hostile_hosts)

	"""
	@staticmethod
	def getMac(ip):
		res, un = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),\
			timeout=2, retry=10)
		for s, r in res:
			return r[Ether].src
		return None
	"""

	@pyqtSlot('QString')
	def incr(self, ip):
		#h = Host.getHostByMac(mac)
		#if h == None:
		h = self.getHostByIp(ip)
		cur = int(h[5].text())
		h[5].setText(str(cur + 1))

	"""
	@staticmethod
	def getHostByMac(mac):
		for h in Host.__all_hostile_hosts:
			if h.mac().text() == mac:
				return h
		return None
	"""

	def getHostByIp(self, ip):
		for h in self.__all_hostile_hosts:
			if h[0].text() == ip:
				return h
		return None



############################################################
## SSH connection 
############################################################
class Ssh:

	def __init__(self, user, pwd, host):
		self.__u = user
		self.__p = pwd
		self.__h = host

	def connect(self):
		# create a connection first
		self.__conn = paramiko.SSHClient()
		self.__conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			self.__conn.connect(username=self.__u, password=self.__p, hostname=self.__h)
		except Exception as ex:
			return ex

		return 'Connected'

	def execute(self, cmds):
		for cmd in cmds:
			pass

	def clean(self):
		self.__conn.close()

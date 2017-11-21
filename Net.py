
from PyQt5.QtCore import pyqtSlot, QObject, pyqtSignal
from PyQt5.QtWidgets import QTableWidgetItem
import queue
import time
import threading
from subprocess import Popen, PIPE

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
		return '< ' + self[0] + ' | ' + self[1] + ' => ' + self[2] +' | ' + self[3] + ' | ' + \
				('THREAT' if(self[6] == 'YES') else 'NOT_THREAT') + ' >'

	def isThreat(self):
		return True if(self[6] == 'YES') else False



###############################################################
## Server utilities
###############################################################
class LogUtils:

	__in_q  = queue.Queue()
	__msgs  = []

	@staticmethod
	@pyqtSlot('QString')
	def addToInQueue(msg):
		LogUtils.__in_q.put(msg)

	@staticmethod
	def addToList(msg):
		LogUtils.__msgs.append(msg)

	@staticmethod
	def clearList():
		LogUtils.__msgs = []

	@staticmethod
	def getMsgFromList(index):
		return LogUtils.__msgs[index]

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
		is_threat, msg_desc = LogUtils.parseAlert(msg_str)
		tmp = pos + 1
		msg = msg[tmp:]
		pos = msg.find('}')
		proto = msg[:pos]

		tmp = pos + 1
		msg = msg[tmp:]

		ips = msg.split('->')

		#dttm, src_addr, dst_addr, src_prt, dst_prt, proto, fc, sv, msg, is_threat
		return Message(time.asctime(), ips[0], ips[1], proto, sev_fc[0], sev_fc[2], msg_desc, is_threat)

	@staticmethod
	def parseAlert(err):
		if 'Classification' not in err:
			return (True, {0:err})

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




###################################################################
## Network Node
###################################################################
class Host(QObject):

	def __init__(self, ip = '', mac = 'Unknonw', c='1'):
		"""
		constructor
		"""
		super(Host, self).__init__()
		self.ip    = QTableWidgetItem(ip)
		self.mac   = QTableWidgetItem(mac)
		self.count = QTableWidgetItem(c)

	#overload operator
	def __eq__(self, host):
		return (host.ip.text() == self.ip.text())


	def resolveMac(self):
		"""
		resolve the MAC address for this host
		1) send ICMP probes
		2) use 'arp' to check whether this IP has an entry in the ARP cache
		"""
		if HostileHosts.icmpProbe(self.ip.text()):
			m = HostileHosts.getMac(self.ip.text())
			if m:
				self.mac.setText(m)
			else:
				self.mac.setText('Unknown')
		else:
			self.mac.setText('Unknown')




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
			src = self.__hostile_q.get()
			ip = src[:src.rfind(':')]

			h = Host(ip=ip)
			if self.exists(h):
				self.newHostileMsgFromHost_HH.emit(ip)
				#print('Exists')
			else:
				h.resolveMac()
				self.newHostileHost_HH.emit(h)
				self.__all_hostile_hosts.append(h)
				#print('Does not exist')
			try:
				pass
			except Exception as ex:
				print(ex)
				
				
	# utility methods
	@pyqtSlot('QString')
	def addToHostileQueue_HH(self, src):
		self.__hostile_q.put(src)

	def exists(self, h):
		return (h in self.__all_hostile_hosts)


	@pyqtSlot('QString')
	def incr(self, ip):
		#h = Host.getHostByMac(mac)
		#if h == None:
		h = self.getHostByIp(ip)
		cur = int(h.count.text())
		h.count.setText(str(cur + 1))



	def getHostByIp(self, ip):
		for h in self.__all_hostile_hosts:
			if h.ip.text() == ip:
				return h
		return None


	@staticmethod
	def icmpProbe(ip):
		cmd = 'c:\\Windows\\System32\\ping %s -n 3' % ip
		p   = Popen(cmd, shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
		res = p.stdout.read()

		res = res.decode()
		if len(p.stderr.read()) == 0:
			if 'Destination host unreachable' in res:
				return False
			return True
		else:
			return False

	@staticmethod
	def getMac(ip):
		cmd = 'c:\\Windows\\System32\\arp -a %s' % ip
		p   = Popen(cmd, shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
		res = p.stdout.read()

		res = res.decode().strip('\r\n')
		if 'No ARP' in res:
			return False

		res = res.strip('\r\n').replace('\r', '').split('\n')[-1:][0].strip(' ').split(' ')
		fine = []
		for i in res:
			if len(i) > 5:
				fine.append(i)
		return (fine[1] if (len(fine) == 3) else False)

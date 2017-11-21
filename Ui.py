## Imports
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon, QColor, QPalette, QFont
from PyQt5.QtCore import pyqtSlot, Qt, pyqtSignal, QEventLoop, QItemSelectionModel
from PyQt5.QtNetwork import QUdpSocket, QHostAddress
import threading
import paramiko
from time import sleep
import sys
import pickle
import Net


#############################################################
## Main Window class
#############################################################
class MainView(QMainWindow):
	"""
	define the main window display
	"""
	#add a signal
	msgProcessed     = pyqtSignal(Net.Message)
	updateStatusBar  = pyqtSignal('QString')
	newHostileMsg_MW = pyqtSignal('QString')
	dH               = None
	dW               = None
	def __init__(self):
		super(MainView, self).__init__()
		#variables
		self.__to_tray_action  = QAction('Collapse')
		self.__exit_action     = QAction('Quit')
		self.__clr_logs_action = QAction('Clear Logs')
		self.__show_hostile    = QAction('Show Hostile Hosts')
		self.__settings        = QAction('Settings')
		self.__view_menu       = self.menuBar().addMenu('App')

		#server stats
		self.__socket = None
		#system tray
		self.__sys_tray_icon = SystemTrayIcon()
		#a list of hostile hosts
		self.__hhview = HostileHostsView()

	@staticmethod
	def initDesktopSize():
		d = QApplication.desktop()
		rect = d.availableGeometry()
		MainView.dW = rect.width()
		MainView.dH = rect.height()


	def initUi(self): 
		"""
		Initialize the main window
		"""
		#self.setGeometry(300, )
		MainView.initDesktopSize()
		#self.setWindowFlags(Qt.FramelessWindowHint)
		self.setWindowTitle('-- Log Server --')
		self.setWindowIcon(QIcon('icons/app.png'))
		self.setGeometry(100,100,1150, 600)
		#self.setSize(1050, 600)
		self.createMenuBar()
		self.createCenterWidget()
		self.createStatusBar()
		self.initSysTray()
		self.initHostileHostsView()
		self.setContentsMargins(0,5,0,0)
		self.style()
		self.setVisible(True)

	def style(self):
		"""
		style the main window
		"""
		f = QFont('Lucida Console, Courier, monospace')
		#f.setBold(True)
		p = QPalette()
		p.setColor(QPalette.Window, QColor('#fff'))
		p.setColor(QPalette.WindowText, QColor('black'))
		
		#p.setColor(QPalette.)
		self.setPalette(p)
		self.setFont(f)

	def initHostileHostsView(self):
		self.__hhview.initView()
		self.__sys_tray_icon.setHHVVisible.connect(self.__hhview.showHHView)
		self.newHostileMsg_MW.connect(self.__hhview.addToHostileQueue_HHV)
		self.__hhview.newHostileAlert.connect(self.__sys_tray_icon.alert_STI)
		self.__show_hostile.triggered.connect(self.__hhview.show)

	def initSysTray(self):
		"""
		initialize system tray parameters
		"""
		self.__sys_tray_icon.initIcon()
		#connections
		self.__sys_tray_icon.exited.connect(self.stopServer)
		self.__sys_tray_icon.setHomeVisible.connect(self.showHome)
		#self.__sys_tray_icon.attacksClicked.connect()
		self.__sys_tray_icon.activated.connect(self.trayIconActivated)


	#re-implement this method to control how close is handled
	def closeEvent(self, event):
		event.ignore()
		self.__to_tray_action.triggered.emit()
		

	def createMenuBar(self):
		"""
		create the menu bar
		"""
		self.__view_menu.addAction(self.__to_tray_action)
		self.__view_menu.addAction(self.__clr_logs_action)
		self.__view_menu.addAction(self.__exit_action)
		self.__view_menu.addAction(self.__show_hostile)
		self.__view_menu.addAction(self.__settings)

		#connections (SIGNAL <--> SLOT)
		self.__exit_action.triggered.connect(self.stopServer)
		self.__to_tray_action.triggered.connect(self.showHome)
		self.__settings.triggered.connect(self.showSettings)

	@pyqtSlot()
	def showSettings(self):
		"""
		display settings, modify settings
		"""
		el   = QEventLoop()
		sett = Configs()
		sett.exit.connect(el.exit)
		sett.show()
		el.exec()


	def createCenterWidget(self):
		"""
		create and add a center widget
		"""
		self.__cv = CenterView()
		self.__cv.initCenter()
		self.setCentralWidget(self.__cv)

		#connect CenterView's add() to a signal
		self.msgProcessed.connect(self.__cv.addLog_CV)
		self.__clr_logs_action.triggered.connect(self.__cv.clearLogs_CV)

	def createStatusBar(self):
		"""
		create and add the status bar
		"""
		self.__status_bar = self.statusBar()
		self.updateStatusBar.connect(self.__status_bar.showMessage)


	def process(self):
		"""
		process snort messages
		"""
		while True:
			# read a message from Net.LogUtils.__in_queue
			msgStr = Net.LogUtils.getFromInQueue()
			msgObj = Net.LogUtils.parseMsg(msgStr)
			#emit signal
			self.msgProcessed.emit(msgObj)
			self.updateStatusBar.emit(msgObj.__str__())
			if msgObj.isThreat():
				self.newHostileMsg_MW.emit(msgObj[1])

	def startServer(self):
		"""
		start the log server
		"""
		self.__socket = QUdpSocket()
		self.__socket.bind(QHostAddress.LocalHost,514)
		#connect readReady to a method that can read dgrams from the socket
		self.__socket.readyRead.connect(self.readDgram)
		#use different thread to do processing
		prcssr = threading.Thread(target=self.process)
		prcssr.setDaemon(True)
		prcssr.start()

	#@pyqtSlot()
	def stopServer(self):
		"""
		stop the log server
		"""
		#close socket
		butt = QMessageBox.question(self, 'Log Server',\
				'Are you sure you want to shutdown this Log Server?')
		if butt == QMessageBox.No:
			pass
		else:
			self.__socket.close()
			self.__sys_tray_icon.setVisible(False)
			#self.__hhview.close()
			sys.exit()

	# SLOTS
	@pyqtSlot()
	def readDgram(self):
		try:
			dgram = self.__socket.receiveDatagram()
			dgram = (dgram.data().data()).decode('utf-8')
			if dgram.startswith('<'):
				p = dgram.find('>')
				dgram = dgram[(p + 1):]
			#add to queue
			Net.LogUtils.addToInQueue(dgram)
		except:
			pass

	@pyqtSlot(QSystemTrayIcon.ActivationReason)
	def trayIconActivated(self, reason):
		"""
		handle tray icon activation event
		"""
		if reason == QSystemTrayIcon.Trigger:
			if not self.isVisible():
				self.showHome(True)
			else:
				self.showHome(False)

	@pyqtSlot(bool)
	def showHome(self, boolVal=False):
		if boolVal:
			if not self.isVisible():
				#set visible
				self.show()
				#disable maximize
				self.__sys_tray_icon.setMaxEnabled(False)
				#enable minimize
				self.__sys_tray_icon.setMinEnabled(True)
			else:
				pass
		else:
			if self.isVisible():
				#hide
				self.hide()
				#enable maximize
				self.__sys_tray_icon.setMaxEnabled(True)
				#disable minimize
				self.__sys_tray_icon.setMinEnabled(False)
			else:
				pass


#######################################################
## Center Widget
#######################################################
class CenterView(QSplitter):
	
	logAdded_CV    = pyqtSignal(Net.Message)
	logsCleared_CV = pyqtSignal()
	def __init__(self): 
		"""
		constructor
		"""
		super(CenterView, self).__init__(Qt.Vertical)
		self.__logs = LogsView()
		self.__desc = MessageView()

	def initCenter(self):
		"""
		initialize the center view
		"""
		self.__logs.initView()
		self.addWidget(self.__logs)
		self.addWidget(self.__desc)
		#connections
		self.logAdded_CV.connect(self.__logs.addLog_L)
		self.logsCleared_CV.connect(self.__logs.clearLogs_L)
		self.__logs.rowClicked.connect(self.__desc.updateMsgView)
		self.setContentsMargins(20, 40, 20, 10)
		self.style()

	def style(self):
		"""
		style the logs view
		"""
		#self.__logs.setWindowIcon(QIcon('icons\\notf.png'))
		p = QPalette()
		p.setColor(QPalette.Text, QColor('green'))
		#p.setColor(QPalette.Base, QColor('black'))
		p.setColor(QPalette.Base, QColor('#000'))
		self.setPalette(p)

	@pyqtSlot(Net.Message)
	def addLog_CV(self, msg):
		self.logAdded_CV.emit(msg)

	@pyqtSlot()
	def clearLogs_CV(self):
		self.logsCleared_CV.emit()


#######################################################
## Message View Class
#######################################################
class MessageView(QGroupBox):
	#win = QWidget()
	def __init__(self):
		super(MessageView, self).__init__("  Message Description  ")
		#self.__md = QLabel('wertyuiop[')
		self.__ly = QVBoxLayout()
		self.__ly.addWidget(QTreeWidget())
		self.setLayout(self.__ly)	
		self.setContentsMargins(15, 15, 15, 15)

	@pyqtSlot(Net.Message)
	def updateMsgView(self, msg):
		#update message description form
		#print('Here')
		self.__ly.takeAt(0)
		self.__ly.addWidget(MessageView.getView(msg))

	@staticmethod
	def getView(msg):
		# a tree widget
		lbls = [('Date','Date and Time'), ('Src','Packet Source'), ('Dest','Packet Destination'), ('Proto','Packet Protocol'), \
				('Fac','Facility'), ('Sev','Severity'), ('Threat ?', 'Is_Threat'),(['Error Msg', 'Classification', 'Priority'], \
					'Snort Message Description')]
		tree = QTreeWidget()
		lst = []
		for i in range(len(lbls)):
			prnt = QTreeWidgetItem()
			prnt.setText(0, lbls[i][1])
			if i == 7:
				m = msg[7]
				for j in range(len(m)):
					ch = QTreeWidgetItem()
					ch.setText(0, lbls[i][0][j].ljust(20,'.') + m[j].rjust(50,'.'))
					prnt.addChild(ch)
			else:
				ch = QTreeWidgetItem()
				ch.setText(0, lbls[i][0].ljust(20,'.') + msg[i].rjust(50,'.'))
				prnt.addChild(ch)
			# add item to list
			lst.append(prnt)

		tree.addTopLevelItems(lst)
		tree.expandAll()
		return tree


#######################################################
## Logs View
#######################################################
class LogsView(QGroupBox):

	rowClicked = pyqtSignal(Net.Message)
	def __init__(self):
		"""
		constructor
		"""
		super(LogsView, self).__init__("  Snort Log Messages  ")
		self.__c = 0
		self.__tb = QTableWidget()		
		self.__ly = QVBoxLayout()
		#connections
		self.__tb.itemSelectionChanged.connect(self.focusedRow)
		self.setContentsMargins(15, 15, 15, 15)

	def initView(self):
		#self.__tb.setRowCount(10000)
		self.__tb.setEditTriggers(QAbstractItemView.NoEditTriggers);
		self.__tb.setSelectionBehavior(QAbstractItemView.SelectRows);
		self.__tb.setSelectionMode(QAbstractItemView.SingleSelection);
		self.__tb.verticalHeader().setVisible(False)
		self.__tb.setShowGrid(False)

		headers = ['Date_Time','Source','Destination','Protocol','Facility','Severity','Is Threat','Message']
		self.__tb.setColumnCount(len(headers))
		self.__tb.setColumnWidth(0, 200)
		self.__tb.setColumnWidth(1, 200)
		self.__tb.setColumnWidth(2, 200)
		self.__tb.setColumnWidth(5, 100)
		self.__tb.setColumnWidth(5, 100)
		self.__tb.setColumnWidth(7, 200)	
		self.__tb.setHorizontalHeaderLabels(headers)
		self.__ly.addWidget(self.__tb)
		self.setLayout(self.__ly)

	#style view
	def style(self):
		pass

	# SLOTS
	@pyqtSlot(Net.Message)
	def addLog_L(self, msg):
		#print('$$ ADDED $$')
		self.__tb.setRowCount(self.__c + 1)
		for i in range(8):
			if i == 7:
				self.__tb.setItem(self.__c, i, QTableWidgetItem(msg[i][0]))
			else:
				self.__tb.setItem(self.__c, i, QTableWidgetItem(msg[i]))

		self.__c += 1
		Net.LogUtils.addToList(msg)

	@pyqtSlot()
	def clearLogs_L(self):
		self.__tb.clearContents()
		self.__c = 0
		# clear list
		Net.LogUtils.clearList()

	@pyqtSlot()
	def focusedRow(self):
		row = self.__tb.currentRow()
		if self.__c != 0:
			self.rowClicked.emit(Net.LogUtils.getMsgFromList(row))



##########################################################
## System Tray Icon
##########################################################
class SystemTrayIcon(QSystemTrayIcon):

	exited         = pyqtSignal()
	setHomeVisible = pyqtSignal(bool)
	setHHVVisible  = pyqtSignal()

	def __init__(self):
		"""
		constructor
		"""
		super(SystemTrayIcon, self).__init__(QIcon('icons/app.png'))
		#context menu
		self.__menu    = QMenu()
		self.__exit    = QAction('Quit')
		self.__attacks = QAction('Hostile Hosts')
		self.__max     = QAction('Show Main')
		self.__min     = QAction('Hide Main')
		#self.__stats   = QAction('Statistics')

	def initIcon(self):
		#set visible
		#add actions
		self.__menu.addAction(self.__exit)
		self.__menu.addAction(self.__attacks)
		self.__menu.addAction(self.__max)
		self.__menu.addAction(self.__min)
		#self.__menu.addAction(self.__stats)
		self.style()
		self.setContextMenu(self.__menu)
		self.show()

		#set defaults
		self.__max.setEnabled(False)
		self.setToolTip('Mr. Rop Log Server')

		#connections
		self.__exit.triggered.connect(self.exit)
		self.__attacks.triggered.connect(self.showHHosts)
		self.__max.triggered.connect(self.maximize)
		self.__min.triggered.connect(self.minimize)
		# style
		

	def style(self):
		"""
		style
		"""
		self.__menu.setStyleSheet('QMenu.item { background-color: #444; }')

	@pyqtSlot('QString')
	def alert_STI(self, msg):
		self.showMessage('Logs', msg, QSystemTrayIcon.Warning)

	def setMinEnabled(self, boolVal):
		self.__min.setEnabled(boolVal)

	def setMaxEnabled(self, boolVal):
		self.__max.setEnabled(boolVal)


	# SLOTS
	@pyqtSlot()
	def exit(self):
		self.exited.emit()

	@pyqtSlot()
	def maximize(self):
		self.setHomeVisible.emit(True)

	@pyqtSlot()
	def minimize(self):
		self.setHomeVisible.emit(False)

	@pyqtSlot()
	def showHHosts(self):
		self.setHHVVisible.emit()



#########################################################
## A view to show all sources of attacks
#########################################################
class HostileHostsView(QSplitter):

	# new hostile host
	# newHostileHost_HHV        = pyqtSignal('QString')
	newHostileAlert = pyqtSignal('QString')
	def __init__(self):
		"""
		constructor
		"""
		super(HostileHostsView, self).__init__(Qt.Vertical)
		#variables
		self.__c           = 0
		self.__hhosts      = Net.HostileHosts()
		#self.__notf        = Notifications()
		self.__list        = QTableWidget()
		#self.__dlt         = QPushButton('Delete')
		# actions
		self.__deauth      = QPushButton('Deauthenticate')
		self.__add_to_bl   = QPushButton('Blacklist')
		self.__deauth.setEnabled(False)
		self.__add_to_bl.setEnabled(False)
		#connections

		# blacklisted hosts
		self.__bl, self.__cb = HostileHostsView.getBlackListView()
		self.__rm = QPushButton('Remove')
		self.__rm.setEnabled(False)
		self.__rm.setToolTip('Remove host from black list')
		self.__hhosts.newHostileHost_HH.connect(self.addToHostileView)
		self.__add_to_bl.clicked.connect(self.blacklist)
		self.__deauth.clicked.connect(self.deauthenticate)
		self.__rm.clicked.connect(self.unblacklist)
		self.__list.itemSelectionChanged.connect(self.enableButtons)
		self.__bl.itemSelectionChanged.connect(self.enableRm)
		self.setWindowIcon(QIcon('icons/attacks.png'))
		self.setWindowTitle('-- Hostile Hosts --')


	@pyqtSlot()
	def enableButtons(self):
		#self.__act.setEnabled(True)
		#self.__dlt.setEnabled(True)
		if self.__list.currentRow() != -1:
			if not self.__deauth.isEnabled():
				self.__deauth.setEnabled(True)
				self.__add_to_bl.setEnabled(True)
			else:
				pass
		else:
			self.__deauth.setEnabled(False)
			self.__add_to_bl.setEnabled(False)

	@pyqtSlot()
	def enableRm(self):
		if self.__bl.currentRow() != -1:
			if not self.__rm.isEnabled():
				self.__rm.setEnabled(True)
			else:
				pass
		else:
			self.__rm.setEnabled(False)


	def initView(self):
		# hostile list
		hdrs = ['Ip Address', 'MAC Address', '# of messages']
		self.__list.setColumnCount(len(hdrs))
		self.__list.setColumnWidth(0,200)
		self.__list.setColumnWidth(1,200)
		self.__list.setColumnWidth(2,150)
		self.__list.setHorizontalHeaderLabels(hdrs)
		self.__list.setEditTriggers(QAbstractItemView.NoEditTriggers);
		self.__list.setSelectionBehavior(QAbstractItemView.SelectRows);
		self.__list.setSelectionMode(QAbstractItemView.SingleSelection);
		self.__list.verticalHeader().setVisible(False)
		self.__list.setShowGrid(True);
		# right-center the view 
		y       = (MainView.dH/2) - 200
		x       = (MainView.dW - 600)
		self.setGeometry(x, y, 600, 400)

		self.finish()
		self.style()
		# initialize notifications interface
		#self.__notf.initView()
		#style
		self.setContentsMargins(15, 15, 15, 15)
		#self.setWindowFlags(Qt.FramelessWindowHint)

	def style(self):
		"""
		style the view
		"""
		f = QFont('Lucida Console, Courier, monospace')
		#f.setBold(True)
		p = QPalette()
		p.setColor(QPalette.Text, QColor('green'))
		#p.setColor(QPalette.Base, QColor('black'))
		p.setColor(QPalette.Base, QColor('#000'))
		self.setPalette(p)
		self.setFont(f)

	def finish(self):
		# main layout
		#mainly = QVBoxLayout()
		g1 = QGroupBox('Hostile')
		g2 = QGroupBox('Blacklist')
		# black list  layout
		blly   = QVBoxLayout()
		rmly   = QHBoxLayout()
		rmly.addWidget(self.__rm)
		rmly.addStretch()
		blly.addLayout(rmly)
		blly.addWidget(self.__bl)
		g2.setLayout(blly)

		# hostile list layout
		hlly   = QVBoxLayout()
		btnsly = QHBoxLayout()
		btnsly.addWidget(self.__deauth)
		btnsly.addWidget(self.__add_to_bl)
		btnsly.addStretch()
		hlly.addLayout(btnsly)
		hlly.addWidget(self.__list)
		g1.setLayout(hlly)

		###
		self.addWidget(g1)
		self.addWidget(g2)

	# SLOTS
	@pyqtSlot(Net.Host)
	def addToHostileView(self, host):
		self.__list.setRowCount(self.__c + 1)
		#add to list
		self.__list.setItem(self.__c, 0, host.ip)
		self.__list.setItem(self.__c, 1, host.mac)
		self.__list.setItem(self.__c, 2, host.count)
			
		self.__c += 1
		#notify sys admin
		self.notify()

	@pyqtSlot()
	def showHHView(self):
		if not self.isVisible():
			self.setVisible(True)

	@pyqtSlot('QString')
	def addToHostileQueue_HHV(self, src):
		#print("ADDED")
		self.__hhosts.addToHostileQueue_HH(src)

	#@pyqtSlot('QString')
	def notify(self):
		butt = QMessageBox.question(self, 'Hey Sir! you have a new hostile host',\
			'Would you like to view the host\'s information?')

		if butt == QMessageBox.Yes:
				self.showHHView()
		else:
			# send an alert
			self.newHostileAlert.emit('You have a new hostile host')


	def closeEvent(self, event):
		self.hide()
		event.ignore()


	@pyqtSlot()
	def deauthenticate(self):
		"""
		deassociate a PC from an AP/switch
		"""
		if self.__list.selectedItems()[1].text() == 'Unknown':
			QMessageBox.information(self, 'Ssh','The MAC address for %s has not been resolved yet' % \
				 self.__list.selectedItems()[0].text())
		else:
			lp = QEventLoop()
			ssh = SshConnView(self.__list.selectedItems()[1].text(), 'deauth')
			ssh.deathSuccessful.connect(self.deauthenticated)
			ssh.exited.connect(lp.exit)
			ssh.failed.connect(self.error)
			ssh.initView()
			lp.exec()

		self.__list.setCurrentCell(-1, -1)


	@pyqtSlot()
	def blacklist(self):
		"""
		add to black list
		"""
		if self.__list.selectedItems()[1].text() == 'Unknown':
			QMessageBox.information(self, 'Ssh','The MAC address for %s has not been resolved yet' % \
				 self.__list.selectedItems()[0].text())
		else:
			lp = QEventLoop()
			ssh = SshConnView(self.__list.selectedItems()[1].text(), 'add')
			ssh.addSuccessful.connect(self.addToBL)
			ssh.exited.connect(lp.exit)
			ssh.failed.connect(self.error)
			ssh.initView()
			lp.exec()


	@pyqtSlot()
	def unblacklist(self):
		"""
		remove MAc address from black list
		"""
		lp = QEventLoop()
		ssh = SshConnView(self.__bl.selectedItems()[0].text() , 'remove')
		ssh.rmSuccessful.connect(self.rmFromBL)
		ssh.exited.connect(lp.exit)
		ssh.failed.connect(self.error)
		ssh.initView()
		lp.exec()


	@pyqtSlot('QString', 'QString')
	def addToBL(self, mac, gw):
		# get list
		all_macs = Configs.getBlackList()

		if not all_macs:
			all_macs = set()
		if not (mac, gw) in all_macs:
			# add to black list file
			all_macs.add((mac, gw))
			Configs.writeBlckList(all_macs)
			self.__bl.setRowCount(self.__cb + 1)
			self.__bl.setItem(self.__cb, 0, QTableWidgetItem(mac))
			self.__bl.setItem(self.__cb, 1, QTableWidgetItem(gw))
			self.__cb += 1
			self.__list.setCurrentCell(-1, -1)
		else:
			QMessageBox.information(self, '-- error --', '%s is already in the blacklist' % mac)


	@pyqtSlot('QString', 'QString')
	def rmFromBL(self, mac, gw):
		# get all blcklisted mac addresses
		all_macs = Configs.getBlackList()
		if all_macs:
			try:
				all_macs.remove((mac, gw))
				# remove from the view
				for i in range(self.__cb):
					if mac == self.__bl.item(i, 0).text():
						self.__bl.removeRow(i)
						self.__cb -= 1
						self.__bl.setRowCount(self.__cb)
			except:
				pass
			# update blacklisted list file
			Configs.writeBlckList(all_macs)
		self.__bl.setCurrentCell(-1, -1)


	@pyqtSlot('QString', 'QString')
	def error(self, host, action):
		"""
		Applying an action to a host failed
		"""
		err_msg = ('Adding %s to black list failed' % host) if(action == 'add') \
						else ('Removing %s from the blacklist failed' % host) if(action == 'remove') \
								else ('Deauthenticating %s failed' % host)
		QMessageBox.critical(self, '-- error --', err_msg)


	@pyqtSlot('QString', 'QString')
	def deauthenticated(self, host, gw):
		"""
		display
		"""
		QMessageBox.information(self, '-- success --', '%s deauthenticated successfully' % host)



	##########################
	## utility methods
	##########################
	def getBlackListView():
		bl = QTableWidget()
		bl.setColumnCount(2)
		bl.setColumnWidth(0, 250)
		bl.setColumnWidth(1, 250)
		bl.setHorizontalHeaderLabels(['MAC Address', 'Gateway IP'])
		bl.setEditTriggers(QAbstractItemView.NoEditTriggers);
		bl.setSelectionBehavior(QAbstractItemView.SelectRows);
		bl.setSelectionMode(QAbstractItemView.SingleSelection);
		bl.verticalHeader().setVisible(False)
		bl.setShowGrid(False);

		# get black list
		l = Configs.getBlackList()
		if not l:
			return (bl, 0)

		bl.setRowCount(len(l))
		for index, data in enumerate(l):
			bl.setItem(index, 0, QTableWidgetItem(data[0]))
			bl.setItem(index, 1, QTableWidgetItem(data[1]))

		return (bl, len(l))




############################################################
## SSH connection 
############################################################
class SshConnView(QWidget):
	# close signal
	exited          = pyqtSignal()
	rmSuccessful    = pyqtSignal('QString', 'QString')
	addSuccessful   = pyqtSignal('QString', 'QString')
	deathSuccessful = pyqtSignal('QString', 'QString')
	failed          = pyqtSignal('QString', 'QString')

	def __init__(self, host, action):
		super(SshConnView, self).__init__()
		self.__u      = QLineEdit()
		self.__p      = QLineEdit()
		self.__choices, self.__gwip = SshConnView.getIpChoices()
		self.__gwport = QLineEdit()
		self.__c      = QPushButton('connect')
		self.__bck    = QPushButton('Retry')
		self.__h      = host
		self.__a      = action
		self.__conn   = paramiko.SSHClient()
		self.__log    = QTextEdit()
		# signal
		self.__signal = self.rmSuccessful if(action == 'remove') else self.addSuccessful \
								if(action == 'add') else self.deathSuccessful

		# layouts
		self.__ml = QVBoxLayout()
		self.__data = QFrame()



	def initView(self):
		il = QFormLayout()
		self.__c.setEnabled(False)
		self.__log.setReadOnly(True)
		
		il.addRow('Network Gateway Ip', self.__gwip)
		il.addRow('Network Gateway port', self.__gwport)
		il.addRow('SSH Server username', self.__u)
		il.addRow('SSH Server password', self.__p)
		il.addRow('', self.__c)
		self.__p.setEchoMode(QLineEdit.Password)

		#connections
		self.__c.clicked.connect(self.cnnct)
		self.__bck.clicked.connect(self.retry)
		self.__u.textEdited.connect(self.validate)
		self.__p.textEdited.connect(self.validate)
		self.__gwip.currentTextChanged.connect(self.validate)
		self.__gwip.editTextChanged.connect(self.validate)
		self.__gwport.textEdited.connect(self.validate)
		# window styles
		self.setWindowIcon(QIcon('icons\\app.png'))
		self.setWindowTitle('-- SSH_Client --')
		self.setMinimumSize(400, 500)
		#self.__il.addStretch()
		self.__data.setLayout(il)
		self.__ml.addWidget(self.__data)
		self.__ml.addWidget(self.__bck)
		self.__bck.setVisible(False)
		self.__ml.addWidget(self.__log)
		self.setLayout(self.__ml)
		self.style()
		self.show()
		#self.exec_()

	def style(self):
		"""
		style the view
		"""
		f = QFont('Lucida Console, Courier, monospace')
		#f.setBold(True)
		p = QPalette()
		p.setColor(QPalette.Window, QColor('#ddd'))
		p.setColor(QPalette.WindowText, QColor('black'))
		
		#p.setColor(QPalette.)
		self.setPalette(p)
		self.setFont(f)


	@pyqtSlot('QString')
	def validate(self, txt):
		# fill using present data
		if self.__choices.get(self.__gwip.currentText()):
			self.__u.setText(self.__choices[self.__gwip.currentText()]['user'])
			self.__p.setText(self.__choices[self.__gwip.currentText()]['pwd'])
			self.__gwport.setText(self.__choices[self.__gwip.currentText()]['port'])
			self.__c.setEnabled(True)

		else:
			self.__u.clear()
			#self.__gwip.setCurrentIndex(0)
			self.__gwport.clear()
			self.__p.clear()
			#self.__log.clear()
			self.__c.setEnabled(False)

	@pyqtSlot()
	def cnnct(self):
		#SshConnView.action_res = (True, self.__h)
		# create a connection first
		self.__data.setVisible(False)
		self.__bck.setVisible(True)
		#sleep(2)
		self.__conn = paramiko.SSHClient()
		self.__conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			self.__log.append('Connecting to SSH server ... ')
			self.__conn.connect(username=self.__u.text(), password=self.__p.text(), \
				hostname=self.__gwip.currentText(), port=int(self.__gwport.text()))
			#sleep(2)
			self.__log.append('<span style="color:green;"><b>\tCONNECTED :)</b></span>')

			# apply action

		except Exception as ex:
			#return ex
			self.__log.append('<span style="color:red;font-family:Lucida Console, Courier, monospace;"> \
				\tCONNECTION FAILED: </span> %s' % ex )
			self.failed.emit(self.__h, self.__a)

		#emit signal
		self.__signal.emit(self.__h, self.__gwip.currentText())

	@pyqtSlot()
	def retry(self):
		self.__u.clear()
		self.__gwip.setCurrentIndex(0)
		self.__gwport.clear()
		self.__p.clear()
		self.__log.clear()
		self.__c.setEnabled(False)
		# swap views
		self.__data.setVisible(True)
		self.__bck.setVisible(False)


	def execute(self, cmds):
		for cmd in cmds:
			pass

	def closeEvent(self, event):
		if self.__conn:
			self.__conn.close()
		self.exited.emit()


	#############################
	## Utility methods
	#############################
	@staticmethod
	def getIpChoices():
		c = QComboBox()
		#c.setEditable(True)
		c.addItem('-- select or enter IP --')
		data = Configs.getSettingsData()
		if len(data) > 0:
			c.addItems(list(data.keys()))

		return (data, c)


	@staticmethod
	def getCmd(action):
		cmds = {
			'remove':'',
			'add':'',
			'deauth':''
		}

		return cmds[action]





############################################################
## display and modify settings
############################################################
class Configs(QWidget):
	"""
	settings ==> gateways, usernames and passwords
	"""
	exit = pyqtSignal()

	def __init__(self):
		super(Configs, self).__init__()
		# init stuff
		self.setWindowTitle('-- settings --')
		self.setWindowIcon(QIcon('icons/settings.png'))
		self.setMinimumSize(650, 400)
		self.initView()
		self.style()

	def initView(self):
		self.__modif = False
		gb = QGroupBox(' network gateways (SSH server connection infor) ')
		outerly = QVBoxLayout()
		innerly = QVBoxLayout()
		btnsly  = QHBoxLayout()
		# actions
		self.__add = QPushButton('Add')
		self.__rm  = QPushButton('Remove')
		self.__rm.setEnabled(False)
		btnsly.addWidget(self.__add)
		btnsly.addWidget(self.__rm)
		btnsly.addStretch()
		innerly.addLayout(btnsly)
		# table of networks and no. of networks
		self.__nets, self.__c = Configs.getSettingsView()
		innerly.addWidget(self.__nets)
		gb.setLayout(innerly)
		outerly.addWidget(gb)
		self.setLayout(outerly)

		# connections
		self.__add.clicked.connect(self.addNewNetwork)
		self.__rm.clicked.connect(self.removeNetwork)
		self.__nets.itemSelectionChanged.connect(self.enableRm)
		self.__nets.itemChanged.connect(self.setModified)

	@pyqtSlot()
	def enableRm(self):
		if self.__nets.currentRow() != -1:
			if not self.__rm.isEnabled():
				self.__rm.setEnabled(True)
			else:
				pass
		else:
			self.__rm.setEnabled(False)

	def closeEvent(self, event):
		"""
		save changes
		"""
		if self.__modif:
			butt = QMessageBox.question(self,'Save changes?', \
				'The settings have been modified, would you like to save changes before exiting?')
			if butt == QMessageBox.Yes:
				# get new settings
				all_nets = {}
				for i in range(self.__c):
					item = self.__nets.item(i, 0)
					if item and item.text():
						# pack dictS
						sett = {}
						sett['port'] = self.__nets.item(i, 1).text()
						sett['name'] = self.__nets.item(i, 2).text()
						sett['user'] = self.__nets.item(i, 3).text()
						sett['pwd']  = self.__nets.item(i, 4).text()

						all_nets[item.text()] = sett
				# time to save
				#print(all_nets)
				Configs.writeSettings(all_nets)
			else:
				pass
		else:
			pass


	def style(self):
		"""
		style the view
		"""
		self.setContentsMargins(10, 15, 10 , 10)
		f = QFont('Lucida Console, Courier, monospace')
		#f.setBold(True)
		p = QPalette()
		p.setColor(QPalette.Window, QColor('#fff'))
		p.setColor(QPalette.WindowText, QColor('black'))
		
		#p.setColor(QPalette.)
		self.setPalette(p)
		self.setFont(f)


	@pyqtSlot()
	def addNewNetwork(self):
		"""
		add a new network's gateway ssh server connection details
		"""
		self.__c += 1
		self.__nets.setRowCount(self.__c)
		# add
		#self.__nets.setItem(self.__c, 0, QTableWidgetItem(str(self.__c)))
		self.__nets.setItem(self.__c, 0, QTableWidgetItem())
		self.__nets.setItem(self.__c, 1, QTableWidgetItem())
		self.__nets.setItem(self.__c, 2, QTableWidgetItem())
		self.__nets.setItem(self.__c, 3, QTableWidgetItem())
		self.__nets.setItem(self.__c, 4, QTableWidgetItem())
		# set focus to this row
	
	@pyqtSlot()
	def removeNetwork(self):
		if self.__c > 0:
			if self.__nets.currentRow()	!= -1:
				self.__nets.removeRow(self.__nets.currentRow())
				self.__c -= 1
				self.__nets.setRowCount(self.__c)
				self.__nets.setCurrentCell(-1, -1)
				self.__modif = True


	@pyqtSlot(QTableWidgetItem)
	def setModified(self, item):
		self.__modif = True


	#####################
	## Utility methods
	#####################
	@staticmethod
	def getSettingsView():
		"""
		read the configurations json file, parse and create a table
		"""
		c = 0
		tb = QTableWidget()
		hdrs = ['Ip Address','Port', 'Network Name', 'User', 'Password']
		tb.setColumnCount(len(hdrs))
		tb.setRowCount(c)
		tb.setColumnWidth(0,150)
		tb.setColumnWidth(1,60)
		tb.setColumnWidth(2,150)
		tb.setColumnWidth(3,150)
		tb.setColumnWidth(4,150)
		tb.setHorizontalHeaderLabels(hdrs)
		tb.setEditTriggers(QAbstractItemView.DoubleClicked);
		tb.setSelectionBehavior(QAbstractItemView.SelectRows);
		tb.setSelectionMode(QAbstractItemView.SingleSelection);
		tb.verticalHeader().setVisible(False)
		tb.setGridStyle(Qt.DashLine)
		tb.setShowGrid(True);

		data = Configs.getSettingsData()
		if data:
			c = len(data)
			tb.setRowCount(c)
			for index, key in enumerate(list(data.keys())):
				net = data.get(key)
				if net:
					tb.setItem(index, 0, QTableWidgetItem(key))
					tb.setItem(index, 1, QTableWidgetItem(net['port']))
					tb.setItem(index, 2, QTableWidgetItem(net['name']))
					tb.setItem(index, 3, QTableWidgetItem(net['user']))
					tb.setItem(index, 4, QTableWidgetItem(net['pwd']))

		return (tb, c)



	@staticmethod
	def getSettingsData():
		"""
		read the settings file
		"""
		try:
			with open('appData/settings', 'rb') as f:
				data = pickle.load(f)
				return data
		except:
			return False

	@staticmethod
	def getBlackList():
		"""
		read the blacklist file
		"""
		try:
			with open('appData/blacklist', 'rb') as f:
				data = pickle.load(f)
				return data
		except:
			return False


	@staticmethod
	def writeSettings(sett):
		"""
		write the settings to disk
		"""
		with open('appData/settings', 'wb') as f:
			pickle.dump(sett, f)


	@staticmethod
	def writeBlckList(bl):
		"""
		write new blacklist
		"""
		with open('appData/blacklist', 'wb') as f:
			pickle.dump(bl, f)

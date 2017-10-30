## Imports
from PyQt5.QtWidgets import QMainWindow, QAction, QSplitter, QDialog, QWidget, QMenu, QToolButton, QTreeWidget, QFrame, \
							 QLabel, QFormLayout, QTableWidget, QGroupBox, QMessageBox, QHBoxLayout, QTreeWidgetItem, QTextEdit, \
							  QVBoxLayout, QTableWidgetItem, QAbstractItemView, QSystemTrayIcon, QPushButton, QApplication, QLineEdit
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot, Qt, pyqtSignal, QEventLoop
from PyQt5.QtNetwork import QUdpSocket, QHostAddress
import threading
import paramiko
from time import sleep
import sys
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
		self.__to_tray_action  = QAction(QIcon('icons\min.png'),'Collapse')
		self.__exit_action     = QAction(QIcon('icons\close.png'),'Quit')
		self.__clr_logs_action = QAction(QIcon('icons\clear.png'),'Clear Logs')
		self.__view_menu       = self.menuBar().addMenu('LogServer')

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
		self.setWindowTitle('[ RopLogServer ]')
		self.setWindowIcon(QIcon('icons/app.png'))
		self.setGeometry(100,100,1150, 600)
		#self.setSize(1050, 600)
		self.createMenuBar()
		self.createCenterWidget()
		self.createStatusBar()
		self.initSysTray()
		self.initHostileHostsView()
		self.setContentsMargins(0,10,0,0)
		self.setVisible(True)

	def initHostileHostsView(self):
		self.__hhview.initView()
		self.__sys_tray_icon.setHHVVisible.connect(self.__hhview.showHHView)
		self.newHostileMsg_MW.connect(self.__hhview.addToHostileQueue_HHV)
		self.__hhview.newHostileAlert.connect(self.__sys_tray_icon.alert_STI)

	def initSysTray(self):
		"""
		initialize system tray parameters
		"""
		self.__sys_tray_icon.initIcon()
		#connections
		self.__sys_tray_icon.exited.connect(self.close)
		self.__sys_tray_icon.setHomeVisible.connect(self.showHome)
		#self.__sys_tray_icon.attacksClicked.connect()
		self.__sys_tray_icon.activated.connect(self.trayIconActivated)

	#re-implement this method to control how close is handled
	def closeEvent(self, event):
		butt = QMessageBox.question(self, 'Log Server',\
				'Are you sure you want to shutdown this Log Server?')
		if butt == QMessageBox.No:
			event.ignore()
		else:
			self.stopServer()

	def createMenuBar(self):
		"""
		create the menu bar
		"""
		self.__view_menu.addAction(self.__to_tray_action)
		self.__view_menu.addAction(self.__clr_logs_action)
		self.__view_menu.addAction(self.__exit_action)

		#connections (SIGNAL <--> SLOT)
		self.__exit_action.triggered.connect(self.close)
		self.__to_tray_action.triggered.connect(self.showHome)

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
		self.__socket.close()
		self.__sys_tray_icon.setVisible(False)
		self.__hhview.close()

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
		self.__ly.addWidget(QLabel('sdfghjkrtyuio'))
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
		print(row)
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
		self.__exit    = QAction(QIcon('icons\close.png'),'Quit')
		self.__attacks = QAction(QIcon('icons\\notf.png'),'Attacks')
		self.__max     = QAction(QIcon('icons\max.png'),'Expand')
		self.__min     = QAction(QIcon('icons\min.png'),'Collapse')
		#self.__stats   = QAction('Statistics')

	def initIcon(self):
		#set visible
		#add actions
		self.__menu.addAction(self.__exit)
		self.__menu.addAction(self.__attacks)
		self.__menu.addAction(self.__max)
		self.__menu.addAction(self.__min)
		#self.__menu.addAction(self.__stats)
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

	@pyqtSlot('QString')
	def alert_STI(self, msg):
		self.showMessage('Logs', msg, QSystemTrayIcon.Warning)

	def setMinEnabled(self, boolVal):
		self.__min.setEnabled(boolVal)

	def setMaxEnabled(self, boolVal):
		self.__max.setEnabled(boolVal)

	# style view
	def style(self):
		pass

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
class HostileHostsView(QWidget):

	# new hostile host
	# newHostileHost_HHV        = pyqtSignal('QString')
	newHostileAlert = pyqtSignal('QString')
	def __init__(self):
		"""
		constructor
		"""
		super(HostileHostsView, self).__init__()
		#variables
		self.__c           = 0
		self.__hhosts      = Net.HostileHosts()
		#self.__notf        = Notifications()
		self.__list        = QTableWidget()
		self.__dlt         = QPushButton('Delete')
		self.__act         = QPushButton('Actions')
		self.__cls         = QPushButton('Hide')
		self.__action_menu = QMenu()
		# icons
		self.__dlt.setIcon(QIcon('icons\\delete.png'))
		self.__cls.setIcon(QIcon('icons\\close.png'))
		#self.__act.setIcon(QIcon('icons\\list.png'))
		self.__dlt.setToolTip('Delete host from this list')
		self.__cls.setToolTip('Hide this window')
		self.__act.setToolTip('A list of actions')

		# actions
		self.__deauth      = QAction('Deauthenticate')
		self.__add_to_bl   = QAction('Add To Blacklist')
		self.__add_to_wl   = QAction('Add To Watch List')
		#connections
		self.__cls.clicked.connect(self.hide)
		self.__hhosts.newHostileHost_HH.connect(self.addToHostileView)
		self.__add_to_bl.triggered.connect(self.addToBl)
		#self.__hhosts.newHostileMsgFromHost_HH.connect(self.alert_HHV)
		#self.__notf.viewHostileHosts.connect(self.showHHView)
		#default
		#self.__act.setEnabled(False)
		#self.__dlt.setEnabled(False)

	@pyqtSlot()
	def enableButtons(self):
		self.__act.setEnabled(True)
		self.__dlt.setEnabled(True)

	def initView(self):
		hdrs = ['Ip Address', 'MAC Address', 'Host Name', 'Operating System', 'Users', '# of Messages']
		self.__list.setColumnCount(len(hdrs))
		self.__list.setHorizontalHeaderLabels(hdrs)
		self.__list.setEditTriggers(QAbstractItemView.NoEditTriggers);
		self.__list.setSelectionBehavior(QAbstractItemView.SelectRows);
		self.__list.setSelectionMode(QAbstractItemView.SingleSelection);
		self.__list.verticalHeader().setVisible(False)
		self.__list.setShowGrid(False);
		# right-center the view 
		y       = (MainView.dH/2) - 200
		x       = (MainView.dW - 600)
		self.setGeometry(x, y, 600, 400)
		#add layouts
		self.__action_menu.addActions([self.__deauth, self.__add_to_bl, self.__add_to_wl])
		self.__act.setMenu(self.__action_menu)
		self.finish()

		# initialize notifications interface
		#self.__notf.initView()
		#style
		self.setContentsMargins(15, 15, 15, 15)
		#self.setWindowFlags(Qt.FramelessWindowHint)


	def finish(self):
		mly   = QVBoxLayout()
		aly   = QHBoxLayout()
		ely   = QHBoxLayout()
		#add widgets to layouts
		aly.addWidget(self.__act)
		aly.addWidget(self.__dlt)
		aly.addStretch()
		ely.addWidget(self.__cls)
		ely.addStretch()
		mly.addLayout(aly)
		mly.addWidget(self.__list)
		mly.addLayout(ely)
		self.setLayout(mly)

	# SLOTS
	@pyqtSlot(Net.Host)
	def addToHostileView(self, host):
		self.__list.setRowCount(self.__c + 1)
		#add to list
		for i in range(6):
			self.__list.setItem(self.__c, i, host[i])
		self.__c += 1

		#notify sys admin
		self.notify()

	@pyqtSlot(int)
	def removeHost(self, row):
		pass

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
		if not self.isVisible():
			# create a notification 
			m = QMessageBox()
			#m.setWindowFlags(Qt.FramelessWindowHint)
			#m.setSize(600, 400)
			m.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
			m.setText('<b>Hey Sir! you have a new hostile host</b>')
			m.setInformativeText('Would you like to view the host\'s information?')
			val = m.exec()
			if val == QMessageBox.Yes:
				self.showHHView()
		else:
			# send an alert
			self.newHostileAlert.emit('You have a new hostile host')

	"""
	def closeEvent(self, event):
		# close the notifications window too
		self.__notf.close()
	"""

	@pyqtSlot()
	def addToBl(self):
		lp = QEventLoop()
		ssh = SshConnView(self.__list.selectedItems()[1].text(), 'Add to BL')
		ssh.initView()
		ssh.exit.connect(lp.exit)
		lp.exec()



############################################################
## SSH connection 
############################################################
class SshConnView(QWidget):
	# close signal
	exit = pyqtSignal()

	def __init__(self, host, action):
		super(SshConnView, self).__init__()
		self.__u      = QLineEdit()
		self.__p      = QLineEdit()
		self.__gwip   = QLineEdit()
		self.__gwport = QLineEdit('22')
		self.__c      = QPushButton('connect')
		self.__bck    = QPushButton('Retry')
		self.__h      = host
		self.__a      = action
		self.__conn   = paramiko.SSHClient()
		self.__log    = QTextEdit()
		#self.__av     = True
		#self.__sb     = QStatusBar()

		# layouts
		self.__ml = QVBoxLayout()
		self.__data  = QFrame()


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
		self.__gwip.textEdited.connect(self.validate)
		self.__gwport.textEdited.connect(self.validate)
		# window styles
		self.setWindowIcon(QIcon('icons\\notf.png'))
		self.setWindowTitle('Secure_Shell_Client_Interface')
		self.setMinimumSize(400, 500)
		#
		#self.__il.addStretch()
		self.__data.setLayout(il)
		self.__ml.addWidget(self.__data)
		self.__ml.addWidget(self.__bck)
		self.__bck.setVisible(False)
		self.__ml.addWidget(self.__log)
		self.setLayout(self.__ml)
		self.show()
		#self.exec_()

	@pyqtSlot('QString')
	def validate(self, txt):
		if self.__u.text() and self.__p.text() and self.__gwport.text() and self.__gwip.text():
			self.__c.setEnabled(True)
		else:
			self.__c.setEnabled(False)

	@pyqtSlot()
	def cnnct(self):
		# create a connection first
		self.__data.setVisible(False)
		self.__bck.setVisible(True)
		#sleep(2)
		self.__conn = paramiko.SSHClient()
		self.__conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			self.__log.append('<b> Connecting to SSH server ... </b>')
			self.__conn.connect(username=self.__u.text(), password=self.__p.text(), \
				hostname=self.__gwip.text(), port=int(self.__gwport.text()))
			#sleep(2)
			self.__log.append('<span style="color:green;"><b> CONNECTED </b></span>')
		except Exception as ex:
			#return ex
			self.__log.append('<b> Connection failed : %s </b>' % ex )

		#return 'Connected'

	@pyqtSlot()
	def retry(self):
		self.__u.clear()
		self.__gwport.setText('22')
		self.__gwip.clear()
		self.__gwport.clear()
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
		self.exit.emit()

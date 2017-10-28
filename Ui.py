## Imports
from PyQt5.QtWidgets import QMainWindow, QAction, QSplitter, QDialog, QWidget, QMenu, QToolButton, \
							 QLabel, QFormLayout, QTableWidget, QGroupBox, QMessageBox, QHBoxLayout, \
							  QVBoxLayout, QTableWidgetItem, QAbstractItemView, QSystemTrayIcon, QPushButton, QApplication
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot, Qt, pyqtSignal, QEventLoop
from PyQt5.QtNetwork import QUdpSocket, QHostAddress
import threading
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
		self.__hhview.newHostileMsgFromHost_HHV.connect(self.__sys_tray_icon.alert_STI)

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

	def __init__(self):
		super(MessageView, self).__init__("  Message Description  ")
		self.__ly = QVBoxLayout()
		self.__fm = QFormLayout()
		#self.__ly.addLayout(self.__fm)
		self.setLayout(self.__fm)
		#labels
		self.__src   = QLabel()
		self.__dst   = QLabel()
		self.__dttm  = QLabel()
		self.__proto = QLabel()
		self.__fc    = QLabel()
		self.__sv    = QLabel()
		self.__msg   = QLabel()
		self.__thrt  = QLabel()
		# demo
		#self.__fm.addRow("Source : ", QLabel("172.99.1.3:4564"))
		self.__fm.addRow('Source', self.__src)
		self.__fm.addRow('Destination', self.__dst)
		self.__fm.addRow('Date Time', self.__dttm)
		self.__fm.addRow('Protocol', self.__proto)
		self.__fm.addRow('Facility', self.__fc)
		self.__fm.addRow('Severity', self.__sv)
		self.__fm.addRow('Threat ?', self.__thrt)
		self.__fm.addRow('Message', self.__msg)
		self.setContentsMargins(15, 15, 15, 15)


	@pyqtSlot(Net.Desc)
	def updateMsgView(self, msg):
		#update message description form
		#print('Here')
		self.__dttm.setText(msg[0])
		self.__src.setText(msg[1])
		self.__dst.setText(msg[2])
		self.__proto.setText(msg[3])
		self.__fc.setText(msg[4])
		self.__sv.setText(msg[5])
		self.__thrt.setText(msg[6])
		self.__msg.setText(msg[7])


	@staticmethod
	def getView(msg):
		# a tree widget
		pass


#######################################################
## Logs View
#######################################################
class LogsView(QGroupBox):

	rowClicked = pyqtSignal(Net.Desc)
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
			self.__tb.setItem(self.__c, i, QTableWidgetItem(msg[i]))

		self.__c += 1

	@pyqtSlot()
	def clearLogs_L(self):
		self.__tb.clearContents()
		self.__c = 0

	@pyqtSlot()
	def focusedRow(self):
		items = {}
		row = self.__tb.selectedItems()
		if len(row) == 8:
			for i in range(8):
				items[i] = row[i].text()
			self.rowClicked.emit(Net.Desc(items))


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
	def alert_STI(self, ip):
		self.showMessage('Logs','A new hostile packet from ' + ip, QSystemTrayIcon.Warning)

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
	newHostileMsgFromHost_HHV = pyqtSignal('QString')
	def __init__(self):
		"""
		constructor
		"""
		super(HostileHostsView, self).__init__()
		#variables
		self.__c           = 0
		self.__hhosts      = Net.HostileHosts()
		self.__notf        = Notifications()
		self.__list        = QTableWidget()
		self.__dlt         = QPushButton('Delete')
		self.__act         = QPushButton('Actions')
		self.__cls         = QPushButton('Hide')
		self.__action_menu = QMenu()
		# icons
		self.__dlt.setIcon(QIcon('icons\\delete.png'))
		self.__cls.setIcon(QIcon('icons\\close.png'))
		self.__act.setIcon(QIcon('icons\\list.png'))
		self.__dlt.setToolTip('Delete host from this list')
		self.__cls.setToolTip('Hide this window')
		self.__act.setToolTip('A list of actions')

		# actions
		self.__deauth      = QAction('Deauthenticate')
		self.__ignore      = QAction('Ignore')
		#connections
		self.__cls.clicked.connect(self.hide)
		self.__hhosts.newHostileHost_HH.connect(self.addToHostileView)
		self.__hhosts.newHostileMsgFromHost_HH.connect(self.alert_HHV)
		self.__notf.viewHostileHosts.connect(self.showHHView)
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
		self.__action_menu.addActions([self.__deauth, self.__ignore])
		self.__act.setMenu(self.__action_menu)
		self.finish()

		# initialize notifications interface
		self.__notf.initView()
		#style
		self.setContentsMargins(15, 15, 15, 15)
		self.setWindowFlags(Qt.FramelessWindowHint)


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
		self.notify(host[0].text())

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

	@pyqtSlot('QString')
	def alert_HHV(self, ip):
		self.newHostileMsgFromHost_HHV.emit(ip)

	#@pyqtSlot('QString')
	def notify(self, ip):
		self.__notf.add(ip)
		self.__notf.setVisible(True)

	def closeEvent(self, event):
		# close the notifications window too
		self.__notf.close()

#############################################################
## Notification --> about a new hostile host
#############################################################
class Notifications(QDialog):

	viewHostileHosts = pyqtSignal()
	def __init__(self):
		"""
		constructor
		"""
		super(Notifications, self).__init__()
		self.__lab    = QLabel()
		self.__view   = QPushButton('View')
		self.__ignore = QPushButton('Ignore')
		self.__list   = []

		self.__lab.setWordWrap(True)
		self.__view.clicked.connect(self.view)
		self.__ignore.clicked.connect(self.ignoreAlert)

	def initView(self):
		mly  = QVBoxLayout()
		b1ly = QHBoxLayout()
		b2ly = QHBoxLayout()
		bly  = QHBoxLayout()
		#ily  = QHBoxLayout()
		# configs
		self.setGeometry((MainView.dW - 420), ( MainView.dH - 150), 400, 100)
		self.setWindowFlags(Qt.FramelessWindowHint)
		self.__lab.setAlignment(Qt.AlignCenter)
		# add widgets to layout managers
		#ily.addWidget(self.__lab)
		b1ly.addWidget(self.__view)
		b2ly.addWidget(self.__ignore)
		b1ly.addStretch()
		b1ly.setAlignment(Qt.AlignCenter)
		b2ly.addStretch()
		b2ly.setAlignment(Qt.AlignCenter)
		bly.addLayout(b1ly)
		bly.addLayout(b2ly)
		mly.addWidget(self.__lab)
		mly.addLayout(bly)
		mly.setSpacing(10)
		#mly.setAlignment(Qt.AlignCenter)
		self.setLayout(mly)


	def updateNotf(self, ip):
		self.__lab.setText('You have %d hostile hosts : <b>%s</b>' % (len(self.__list), str(self.__list)))

	def add(self, ip):
		self.__list.append(ip)
		self.updateNotf(ip)

	@pyqtSlot()
	def view(self):
		self.__lab.setText('<b>0 hostile hosts</b>')
		self.__list = []
		self.setVisible(False)
		self.viewHostileHosts.emit()

	@pyqtSlot()
	def ignoreAlert(self):
		self.setVisible(False)

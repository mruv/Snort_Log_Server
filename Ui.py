
from PyQt5.QtWidgets import (
			QMainWindow, QMenu, QSplitter, QAction, QTableWidget, QTableWidgetItem,
			QGroupBox, QPushButton, QVBoxLayout, QHBoxLayout, QAbstractItemView, QSystemTrayIcon,
			QMessageBox, QFormLayout, QLineEdit, QLabel, QDialog, QTextEdit, QFrame, QStatusBar
			)
from PyQt5.QtCore import (pyqtSlot, pyqtSignal, Qt, QEventLoop)
from PyQt5.QtGui import (QPalette, QFont, QColor, QIcon)
from subprocess import (Popen, PIPE)
from queue import Queue
import sys
import time
import threading
import re
import Util



class NotifWidget(QDialog):
	""" Notify admin about a new hostile host
	"""

	NOTIF_Q       = Queue()
	NOTIF_VISIBLE = False

	def __init__(self, ip):
		super(NotifWidget, self).__init__()

		self.__ip = QLabel(ip)
		self.setWindowTitle('Notification')
		self.setWindowIcon(QIcon('icons/app.png'))
		self.setFixedSize(600, 400)


	def style(self):

		#self.setStyleSheet('background-color: #eee')
		self.__hdr.setStyleSheet('color: blue; font-size: 36px;margin-top: 20px;\
			font-family:"Lucida Console, Courier";')
		self.__hdr.setAlignment(Qt.AlignCenter)

		self.__bdy.setStyleSheet('color: #333; font-size: 24px;\
			font-family:"Lucida Console, Courier, monospace";margin-top: 50px;')
		self.__bdy.setAlignment(Qt.AlignCenter)

		self.__ip.setStyleSheet('color: red; font-size: 30px;\
			font-family:"Lucida Console, Courier, monospace";')
		self.__ip.setAlignment(Qt.AlignCenter)


	def set_up_notif_widget(self):

		self.__hdr = QLabel('Hello Mr. Rop!')
		self.__bdy = QLabel('You have a new hostile host')
		self.__ly  = QVBoxLayout(self)
		self.__b_ly = QHBoxLayout()

		self.__ign_btn = QPushButton('Ignore')
		self.__vw_btn  = QPushButton('View')

		self.__ign_btn.clicked.connect(self.ignore)
		self.__vw_btn.clicked.connect(self.view)

		self.__b_ly.addStretch()
		self.__b_ly.addWidget(self.__vw_btn)
		self.__b_ly.addWidget(self.__ign_btn)
		self.__b_ly.addStretch()

		self.__ly.addWidget(self.__hdr)
		self.__ly.addWidget(self.__bdy)
		self.__ly.addWidget(self.__ip)
		self.__ly.addStretch()
		self.__ly.addLayout(self.__b_ly)

		self.style()



	def closeEvent(self, event):

		butt = QMessageBox.question(self, 'New Hostile Host', 'Are you sure you want to ignore this notification?')

		if butt == QMessageBox.Yes:
			self.done(0)
		else:
			event.ignore()

	@pyqtSlot()
	def view(self):
		""" view the hostile host
		"""
		self.done(1)

	@pyqtSlot()
	def ignore(self):
		""" ignore the notification
		"""
		self.done(0)




class StatusBar(QStatusBar):
	""" customize the status bar
	"""

	def __init__(self):
		super(StatusBar, self).__init__()

		self.__all = 0
		self.__anom = 0
		self.__splitter = QSplitter(Qt.Horizontal)
		self.__msg = QLabel()
		self.__msg.setMinimumWidth(600)
		self.setStyleSheet('background-color: #bbb')
		self.__msg.setStyleSheet('color: blue')

		self.__all_lbl = QLabel()
		self.__all_lbl.setStyleSheet('color: blue')
		self.__anom_lbl = QLabel()
		self.__anom_lbl.setStyleSheet('color: red')


	def set_up_statusbar(self):

		self.__frm_1 = QFrame()
		self.__frm_2 = QFrame()
		self.__ly_1 = QHBoxLayout(self.__frm_1)
		self.__ly_2 = QHBoxLayout(self.__frm_2)

		self.__frm_1.setMinimumWidth(200)
		self.__frm_2.setMinimumWidth(200)

		# add widgets to layouts
		self.__anom_nm = QLabel('Threats : ')
		self.__all_nm = QLabel('All Packets : ')
		self.__ly_1.addWidget(self.__all_nm)
		self.__ly_1.addWidget(self.__all_lbl)
		self.__ly_1.addStretch()
		self.__ly_2.addWidget(self.__anom_nm)
		self.__ly_2.addWidget(self.__anom_lbl)
		self.__ly_2.addStretch()

		self.addWidget(self.__msg)
		self.addWidget(self.__frm_1)
		self.addWidget(self.__frm_2)


	@pyqtSlot()
	def incr_no_of_attacks(self):
		""" increment the count of the attacks / messages about some anomolous packet
		"""
		self.__anom += 1
		self.__anom_lbl.setText(str(self.__anom))


	@pyqtSlot('QString')
	def incr_all_pkts(self, msg):
		""" increment the no of messages / packets received by log server
		"""

		self.__msg.setText(msg)

		self.__all += 1
		self.__all_lbl.setText(str(self.__all))


class SystemTrayIcon(QSystemTrayIcon):
	""" run the server the background, use this icon to display the main window
	"""

	close_app = pyqtSignal()
	show_app = pyqtSignal()

	def __init__(self):

		super(SystemTrayIcon, self).__init__()
		self.set_up_icon()

	def set_up_icon(self):
		""" set an icon, add a menu and add actions to the menu
		"""
		self.__menu = QMenu()
		self.__show = QAction("Show")
		self.__quit = QAction("Quit")

		# signals --> slots
		self.__show.triggered.connect(self.show_app_slot)
		self.__quit.triggered.connect(self.close_app_slot)

		self.__menu.addActions([self.__show, self.__quit])
		self.setIcon(QIcon('icons/app.png'))
		self.setContextMenu(self.__menu)


	@pyqtSlot()
	def close_app_slot(self):
		self.close_app.emit()


	@pyqtSlot()
	def show_app_slot(self):
		self.setVisible(False)
		self.show_app.emit()



class Logs(QTableWidget):
	""" display snort log messages here
	"""

	stop_server = pyqtSignal()
	new_alert = pyqtSignal('QString')

	another_msg = pyqtSignal('QString')
	another_anom_msg = pyqtSignal()



	def __init__(self):

		super(Logs, self).__init__()
		
		# start udp server worker

		self.__server_worker = Util.UdpServerWorker()
		self.__server_worker.finished.connect(self.__server_worker.deleteLater)
		self.__server_worker.finished.connect(self.__server_worker.close_socket)
		self.__server_worker.finished_processing_msg.connect(self.add_to_logs)	
		self.stop_server.connect(self.__server_worker.quit)
		
		self.__server_worker.start()
		self.__cnt = 0


	def style(self):
		""" style the view
		"""
		f = QFont('Lucida Console, Courier, monospace')
		#f.setBold(True)
		p = QPalette()
		p.setColor(QPalette.Text, QColor(0, 255, 255))
		#p.setColor(QPalette.Base, QColor('black'))
		p.setColor(QPalette.Base, QColor('#000'))
		self.setPalette(p)
		self.setFont(f)


	def set_up_widget(self):
		""" initialize table view
		"""
		
		self.setEditTriggers(QAbstractItemView.NoEditTriggers);
		self.setSelectionBehavior(QAbstractItemView.SelectRows);
		self.setSelectionMode(QAbstractItemView.SingleSelection);
		self.verticalHeader().setVisible(False)
		self.setShowGrid(False)

		headers = ['Date/Time','Source','Destination','Protocol','Facility','Severity','Is Threat','Message']
		self.setColumnCount(len(headers))
		self.setColumnWidth(0, 150)
		self.setColumnWidth(1, 150)
		self.setColumnWidth(2, 150)
		self.setColumnWidth(5, 100)
		self.setColumnWidth(5, 100)
		self.setColumnWidth(7, 150)
		self.setHorizontalHeaderLabels(headers)

		self.style()

	@pyqtSlot(dict)
	def add_to_logs(self, msg):
		""" a new message (has been processed already)
		"""

		self.setRowCount(self.__cnt + 1)

		self.setItem(self.__cnt, 0, QTableWidgetItem(msg['time']))
		self.setItem(self.__cnt, 1, QTableWidgetItem(msg['src']))
		self.setItem(self.__cnt, 2, QTableWidgetItem(msg['dest']))
		self.setItem(self.__cnt, 3, QTableWidgetItem(msg['proto']))
		self.setItem(self.__cnt, 4, QTableWidgetItem(msg['facility']))
		self.setItem(self.__cnt, 5, QTableWidgetItem(msg['severity']))
		self.setItem(self.__cnt, 6, QTableWidgetItem('YES' if(msg['is_threat']) else 'NO'))
		self.setItem(self.__cnt, 7, QTableWidgetItem(msg['msg']))

		# increment count
		self.__cnt += 1

		self.another_msg.emit(msg['desc'])

		if msg['is_threat']:
			self.new_alert.emit(msg['src'][:msg['src'].rfind(':')])
			self.another_anom_msg.emit()
		


class Hosts(QSplitter):
	""" display blacklisted and hostile hosts
	"""

	mac_resolved = pyqtSignal(int, 'QString')
	view_notif   = pyqtSignal()
	ignore_notif = pyqtSignal('QString')
	next_notif   = pyqtSignal()

	def __init__(self):
		super(Hosts, self).__init__(Qt.Vertical)


	def style(self):
		""" style the view
		"""
		
		p = QPalette()
		p.setColor(QPalette.Text, QColor(0, 255, 255))
		#p.setColor(QPalette.Base, QColor('black'))
		p.setColor(QPalette.Base, QColor('#000'))
		self.setPalette(p)
		#self.setFont(f)


	def set_up_widget(self):

		self.set_up_hostile_hosts_table()
		self.set_up_blacklisted_hosts_table()

		self.setSizes([500, 500])
		self.style()
		#self.setContentsMargins(10, 0, 0, 0)
		

	def set_up_blacklisted_hosts_table(self):
		""" display all blacklisted hosts
		"""
		
		self.__gb1      = QGroupBox('   Black List   ')
		self.__bl_table = QTableWidget()
		self.__bl_table.setEditTriggers(QAbstractItemView.NoEditTriggers);
		self.__bl_table.setSelectionBehavior(QAbstractItemView.SelectRows);
		self.__bl_table.setSelectionMode(QAbstractItemView.SingleSelection);
		self.__bl_table.verticalHeader().setVisible(False)
		self.__bl_table.setShowGrid(False)
		self.__bl_table.setColumnCount(1)

		self.__bl_table.setHorizontalHeaderLabels(['MAC Address'])
		self.__bl_table.setColumnWidth(0, 400)

		# button
		self.__rmv   = QPushButton('Remove')
		self.__rmv.setEnabled(False)
		self.__rmv.clicked.connect(self.rm_from_blacklist)

		# layout managers
		self.__bl_main_ly = QVBoxLayout(self.__gb1)
		self.__bl_bttm_ly = QHBoxLayout()
		self.__bl_bttm_ly.addWidget(self.__rmv)
		self.__bl_bttm_ly.addStretch()
		self.__bl_main_ly.addWidget(self.__bl_table)
		self.__bl_main_ly.addLayout(self.__bl_bttm_ly)

		self.__bl_table.currentCellChanged.connect(self.set_rm_active)
		self.addWidget(self.__gb1)


	def set_up_hostile_hosts_table(self):
		""" display all hostile hosts
		"""
		
		self.__gb2      = QGroupBox('   Hostile Hosts   ')
		self.__hh_table = QTableWidget()
		self.__hh_table.setEditTriggers(QAbstractItemView.NoEditTriggers);
		self.__hh_table.setSelectionBehavior(QAbstractItemView.SelectRows);
		self.__hh_table.setSelectionMode(QAbstractItemView.SingleSelection);
		self.__hh_table.verticalHeader().setVisible(False)
		self.__hh_table.setShowGrid(False)
		self.__hh_table.setColumnCount(3)

		self.__hh_table.setHorizontalHeaderLabels(['IP Address', 'MAC Address', 'Messages'])

		for i in range(3):
			self.__hh_table.setColumnWidth(i, 150)

		# buttons
		self.__add_to_bl   = QPushButton('Blacklist')
		self.__deauth      = QPushButton('Deauthenticate')
		self.__add_to_bl.setEnabled(False)
		self.__deauth.setEnabled(False)
		self.__add_to_bl.clicked.connect(self.add_to_blacklist)
		self.__deauth.clicked.connect(self.rm_from_network)

		# layout managers
		self.__hh_main_ly = QVBoxLayout(self.__gb2)
		self.__hh_bttm_ly = QHBoxLayout()
		self.__hh_bttm_ly.addWidget(self.__add_to_bl)
		self.__hh_bttm_ly.addWidget(self.__deauth)
		self.__hh_bttm_ly.addStretch()
		self.__hh_main_ly.addWidget(self.__hh_table)
		self.__hh_main_ly.addLayout(self.__hh_bttm_ly)

		self.__hh_table.currentCellChanged.connect(self.set_death_bl_active)
		self.mac_resolved.connect(self.set_mac_at)
		self.addWidget(self.__gb2)


	def exists(self, ip):

		for i in range(self.__hh_table.rowCount()):
			if self.__hh_table.item(i, 0).text() == ip:
				return i

		return -1


	def icmp_probe(self, ip):
		""" send ICMP packets, ping utility first sends ARP packets
			in order to resolve IP's MAC address
		"""

		cmd = 'c:\\Windows\\System32\\ping %s -n 10' % ip
		p   = Popen(cmd, shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
		res = p.stdout.read()

		res = res.decode()
		if len(p.stderr.read()) == 0:
			if 'Destination host unreachable' in res:
				return False
			return True
		else:
			return False


	def resolv_mac(self, row, ip):
		""" get MAC from the ARP cache
		"""

		self.icmp_probe(ip)

		cmd = 'c:\\Windows\\System32\\arp -a %s' % ip
		p   = Popen(cmd, shell=True, stdin=PIPE, stderr=PIPE, stdout=PIPE)
		res = p.stdout.read()

		res = res.decode().strip('\r\n')

		mac = ''
		if 'No ARP' not in res:
			res = res.strip('\r\n').replace('\r', '').split('\n')[-1:][0].strip(' ').split(' ')
			fine = []
			for i in res:
				if len(i) > 5:
					fine.append(i)
			mac = (fine[1] if (len(fine) == 3) else 'unknown')
			
		else:
			mac = 'unknown'

		self.mac_resolved.emit(row, mac)


	@pyqtSlot(int, 'QString')
	def set_mac_at(self, row, mac):
		""" set mac address at (row, 1)
		"""
		self.__hh_table.item(row, 1).setText(mac)


	@pyqtSlot('QString')
	def new_alert(self, ip):
		""" notification about a new alert
		"""

		index = self.exists(ip)

		if index >= 0:
			# increment count
			item = self.__hh_table.item(index, 2)
			item.setText(str(int(item.text()) + 1))

		else:

			# add to list
			self.__hh_table.setRowCount(self.__hh_table.rowCount() + 1)
			self.__hh_table.setItem(self.__hh_table.rowCount() - 1, 0, QTableWidgetItem(ip))
			self.__hh_table.setItem(self.__hh_table.rowCount() - 1, 1, QTableWidgetItem('resolving ...'))
			self.__hh_table.setItem(self.__hh_table.rowCount() - 1, 2, QTableWidgetItem(str(1)))

			worker = threading.Thread(target=self.resolv_mac, args=(self.__hh_table.rowCount() - 1, ip))
			worker.setDaemon(True)
			worker.start()

			# alert admin
			if not self.isVisible():
				NotifWidget.NOTIF_Q.put(ip)
				if not NotifWidget.NOTIF_VISIBLE:
					self.next_notif.emit()


	@pyqtSlot()
	def show_next_notif(self):
		
		NotifWidget.NOTIF_VISIBLE = True
		ip = NotifWidget.NOTIF_Q.get()
		notif = NotifWidget(ip)
		notif.set_up_notif_widget()

		notif.finished.connect(notif.deleteLater)

		if notif.exec() == 0:
			if not NotifWidget.NOTIF_Q.empty():
				self.next_notif.emit()
				self.ignore_notif.emit(ip)
		else:
			while not NotifWidget.NOTIF_Q.empty():
				NotifWidget.NOTIF_Q.get()

			NotifWidget.NOTIF_VISIBLE = False
			self.view_notif.emit()



	@pyqtSlot(int, int, int, int)
	def set_death_bl_active(self, cr, cc, pr, pc):

		if not self.__deauth.isEnabled() and not self.__add_to_bl.isEnabled():
			if cr >= 0:
				self.__add_to_bl.setEnabled(True)
				self.__deauth.setEnabled(True)
		else:
			if cr < 0:
				self.__rmv.setEnabled(False)


	@pyqtSlot(int, int, int, int)
	def set_rm_active(self, cr, cc, pr, pc):

		if not self.__rmv.isEnabled():
			if cr >= 0:
				self.__rmv.setEnabled(True)
		else:
			if cr < 0:
				self.__rmv.setEnabled(False)


	@pyqtSlot()
	def add_to_blacklist(self):
		""" add mac address to black list
		"""
		
		# get mac
		row = self.__hh_table.currentRow()
		mac = self.__hh_table.item(row, 1).text()

		if mac == 'unknown' or mac == 'resolving ...':
			qmb = QMessageBox(self)
			qmb.setText('Cannot add machine to black list. Could not resolve MAC address')
			qmb.setWindowTitle('Snort Log Server')
			qmb.setWindowIcon(QIcon('icons\\app.png'))
			qmb.exec()

		else:
			ssh_client = SshClientWidget(mac, 1)
			ssh_client.set_up_ssh_client_widget()
			ssh_client.start_ssh_client_worker()

			ssh_client.exec()


	@pyqtSlot()
	def rm_from_network(self):
		""" deassociate a machine
		"""
		# get mac
		row = self.__hh_table.currentRow()
		mac = self.__hh_table.item(row, 1).text()

		if mac == 'unknown':
			qmb = QMessageBox()
			qmb.setText('Cannot remove machine from the network. Could not resolve MAC address')
			qmb.setWindowTitle('Snort Log Server')
			qmb.setWindowIcon(QIcon('icons\\app.png'))
			qmb.exec()

		else:
			ssh_client = SshClientWidget(mac, 0)
			ssh_client.set_up_ssh_client_widget()
			ssh_client.start_ssh_client_worker()

			ssh_client.exec()


	@pyqtSlot()
	def rm_from_blacklist(self):
		""" remove a machine from black list
		"""
		# get mac
		row = self.__bl_table.currentRow()
		mac = self.__bl_table.item(row, 0).text()

		ssh_client = SshClientWidget(mac, 2)
		ssh_client.set_up_ssh_client_widget()
		ssh_client.start_ssh_client_worker()

		ssh_client.exec()




class MainWindow(QMainWindow):
	""" Main window
	"""

	def __init__(self):
		""" constructor
		"""
		super(MainWindow, self).__init__()
		self.setWindowTitle('Snort Log Server')
		self.setWindowIcon(QIcon('icons/app.png'))
		self.setContentsMargins(0, 7, 0, 0)
		self.setMinimumSize(1000, 600)
		self.showMaximized()
		#self.setGeometry(100, 50, 1200, 600)


	def closeEvent(self, event):
		""" customize how closing the window is handled
		"""

		event.ignore()
		self.hide()
		self.__sys_tray_icon.show()


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


	def set_up_ui(self):

		self.create_menu_bar()
		self.create_center_widget()
		self.create_status_bar()
		self.create_system_tray_icon()
		self.style()


	def create_system_tray_icon(self):
		""" Create and an icon to the system tray
		"""
		self.__sys_tray_icon = SystemTrayIcon()
		self.__sys_tray_icon.setVisible(False)
		self.__sys_tray_icon.show_app.connect(self.show)
		self.__sys_tray_icon.close_app.connect(self.exit_app)



	def create_menu_bar(self):
		""" set up the menu bar
		"""

		# menus
		self.__app_menu = QMenu('App')
		# actions
		self.__clr_logs = QAction('Clear Logs')
		self.__quit     = QAction('Quit')
		self.__hide     = QAction('Hide')

		self.__quit.triggered.connect(self.exit_app)
		self.__hide.triggered.connect(self.set_visible)

		self.__app_menu.addActions([self.__clr_logs, self.__hide, self.__quit])
		self.menuBar().addMenu(self.__app_menu)


	def create_center_widget(self):
		""" initialize and set a widget at the center of the app
		"""
		self.__splitter = QSplitter(Qt.Horizontal)
		self.__logs     = Logs()
		self.__logs.set_up_widget()
		self.__hosts    = Hosts()
		self.__hosts.set_up_widget()

		self.__logs.new_alert.connect(self.__hosts.new_alert)

		self.__gb  = QGroupBox("   Snort Log Messages   ")
		self.__bly = QVBoxLayout(self.__gb)
		self.__bly.addWidget(self.__logs)

		self.__splitter.addWidget(self.__gb)
		self.__splitter.addWidget(self.__hosts)
		self.__splitter.setSizes([1000, 500])

		self.__splitter.setContentsMargins(15, 25, 15, 30)
		self.setCentralWidget(self.__splitter)

		self.__hosts.view_notif.connect(self.show)
		self.__hosts.next_notif.connect(self.__hosts.show_next_notif)
		#self.__hosts.ignore_notif.connect()


	def create_status_bar(self):
		""" create the status bar
		"""
		self.__status_bar = StatusBar()
		self.__status_bar.set_up_statusbar()

		self.setStatusBar(self.__status_bar)

		self.__logs.another_msg.connect(self.__status_bar.incr_all_pkts)
		self.__logs.another_anom_msg.connect(self.__status_bar.incr_no_of_attacks)


	@pyqtSlot()
	def exit_app(self):
		""" close application
		"""
		butt = QMessageBox.question(self, 'Log Server',\
				'Are you sure you want to shutdown this Log Server?')
		if butt == QMessageBox.No:
			pass

		else:
			self.__logs.stop_server.emit()
			self.__sys_tray_icon.setVisible(False)

			#time.sleep(3)
			sys.exit()


	@pyqtSlot()
	def set_visible(self):
		""" hide main window, show tray icon
		"""
		self.hide()
		self.__sys_tray_icon.setVisible(True)



class SshClientWidget(QDialog):
	""" display the progress of an ssh connection
	"""

	close_ssh_connection = pyqtSignal()
	# host, port, user, pwd
	connect_to_ssh_server = pyqtSignal('QString', int, 'QString', 'QString')
	execute_cmd = pyqtSignal('QString')

	def __init__(self, mac, action):
		super(SshClientWidget, self).__init__()

		self.__mac = mac
		self.__act = action

		self.setWindowTitle('SSH Client')
		self.setWindowIcon(QIcon('icons/app.png'))
		self.setFixedSize(600, 400)


	def closeEvent(self, event):
		""" close ssh connection
		"""

		butt = QMessageBox.question(self,'SSH Client', 'Are you sure you want to close this window?')

		if butt == QMessageBox.Yes:
			self.close_ssh_connection.emit()

		else:
			event.ignore()



	def set_up_ssh_client_widget(self):
		""" display controls
		"""

		self.__main_ly = QVBoxLayout(self)
		self.__form_outer_ly = QHBoxLayout()
		self.__form_ly = QFormLayout()
		self.__btn_ly = QHBoxLayout()

		# input fields
		self.__ip = QLineEdit()
		self.__port = QLineEdit('22')
		self.__username = QLineEdit()
		self.__pwd = QLineEdit()
		self.__conn_btn = QPushButton('connect')
		self.__conn_btn.setEnabled(False)
		self.__logs = QTextEdit()

		# place holders
		self.__ip.setPlaceholderText('Ip address')
		self.__port.setPlaceholderText('Port No. (1 - 65535)')
		self.__username.setPlaceholderText('SSH account username')
		self.__pwd.setPlaceholderText('SSH acount password')
		self.__pwd.setEchoMode(QLineEdit.Password)

		# signal -- slot connections
		self.__conn_btn.clicked.connect(self.connect_to_server)
		self.__ip.textEdited.connect(self.validate)
		self.__port.textEdited.connect(self.validate)
		self.__username.textEdited.connect(self.validate)
		self.__pwd.textEdited.connect(self.validate)

		# add to layout
		self.__form_ly.addRow(QLabel('SSH Ip'), self.__ip)
		self.__form_ly.addRow(QLabel('SSH Port'), self.__port)
		self.__form_ly.addRow(QLabel('User Name'), self.__username)
		self.__form_ly.addRow(QLabel('Password'), self.__pwd)

		self.__form_outer_ly.addLayout(self.__form_ly)
		self.__form_outer_ly.addStretch()

		self.__btn_ly.addWidget(self.__conn_btn)
		self.__btn_ly.addStretch()

		self.__main_ly.addLayout(self.__form_outer_ly)
		self.__main_ly.addLayout(self.__btn_ly)
		self.__main_ly.addWidget(self.__logs)

		self.style()


	def style(self):

		f = QFont('Lucida Console, Courier, monospace')
		#f.setBold(True)
		p = QPalette()
		p.setColor(QPalette.Window, QColor('#ddd'))
		p.setColor(QPalette.WindowText, QColor('blue'))
		
		#p.setColor(QPalette.)
		self.setPalette(p)
		self.setFont(f)



	def start_ssh_client_worker(self):
		""" create a worker thread to handle the Ssh connection
		"""
		self.__ssh_client_worker = Util.SshClientWorker()

		self.__ssh_client_worker.finished.connect(self.__ssh_client_worker.deleteLater)
		self.__ssh_client_worker.finished_closing_ssh_connection.connect(
			self.__ssh_client_worker.quit)
		self.__ssh_client_worker.finished_connecting_to_server.connect(
			self.connected_to_server, Qt.DirectConnection)
		self.__ssh_client_worker.finished_executing_cmd.connect(
			self.cmd_result, Qt.DirectConnection)

		self.close_ssh_connection.connect(self.__ssh_client_worker.start_closing_ssh_connection, Qt.DirectConnection)
		self.connect_to_ssh_server.connect(self.__ssh_client_worker.start_connecting_to_server, Qt.DirectConnection)
		self.execute_cmd.connect(self.__ssh_client_worker.start_executing_cmd, Qt.DirectConnection)

		self.__ssh_client_worker.start()


	def get_cmds_queue(self):
		""" generate a queue of commands expected to be executed, with regard to action to be 
			performed : deauthendicate, blacklist ...

			0 --> deauth
			1 --> add to black list
			2 --> remove from black list
		"""
		
		return Queue()


	def is_valid_ip(self, ip):
		try:
			print(re.match(r'^[1-2]{0,1}\d{1,2}.[1-2]{0,1}\d{1,2}.[1-2]{0,1}\d{1,2}.[1-2]{0,1}\d{1,2}$', ip).string)
			return True
		except AttributeError as e:
			print(e)
			return False


	def is_valid_port(self, port):
		if len(port) == 0:
			return False
		else:
			try:
				p = int(port)
				return (p >= 1 and p <= 65535)
			except ValueError:
				return False

	@pyqtSlot('QString')
	def validate(self, new_text):

		if self.is_valid_ip(self.__ip.text()) and \
			self.is_valid_port(self.__port.text()) and \
			len(self.__username.text()) > 0 and \
			len(self.__pwd.text()) > 0:

			self.__conn_btn.setEnabled(True)
		else:
			self.__conn_btn.setEnabled(False)


	@pyqtSlot()
	def connect_to_server(self):
		""" call this method when 'connect' button is hit
		"""

		self.__logs.append('-- connecting to server ...')
		self.connect_to_ssh_server.emit(self.__ip.text(), int(self.__port.text()),\
			self.__username.text(), self.__pwd.text())


	@pyqtSlot(bool, 'QString')
	def connected_to_server(self, is_connected, msg):
		""" called immediately the connection attempt is over
		"""

		if is_connected:
			self.__logs.append('   CONNECTED')



		else:
			self.__logs.append('   CONNECTION FAILED : ' + msg)


	@pyqtSlot(bool, 'QString', 'QString', 'QString')
	def cmd_result(is_success, cmd, output, error):
		""" called after a command has been executed successfully
		"""

		self.__logs.append(output)

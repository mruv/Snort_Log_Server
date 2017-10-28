from PyQt5.QtWidgets import QApplication
import sys
import Ui


if __name__ == '__main__':

	app = QApplication(sys.argv)
	win = Ui.MainView()
	#initiaize and display UI
	win.initUi()
	#start server
	win.startServer()

	sys.exit(app.exec_())

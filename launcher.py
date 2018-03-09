
from PyQt5.QtWidgets import QApplication
import sys

import Ui


def launch(args):
	""" Set up UI and start app
	"""

	app = QApplication(args)

	win = Ui.MainWindow()
	win.set_up_ui()
	#win.setVisible(True)

	app.setQuitOnLastWindowClosed(False)
	# start event loop
	app.exec()


if __name__ == '__main__':
	""" App entry point
	"""
	launch(sys.argv)

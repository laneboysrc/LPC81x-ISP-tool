from distutils.core import setup
import py2exe

setup(
	windows = [{
		'script': 'lpc81x_isp.py',
		'icon_resources': [(0, "laneboysrc.ico")]
	}],
	data_files = [(".", ["laneboysrc.ico"])]
)

# LPC81x-ISP-TOOL - yet another NXP LPC810 / LPC811 / LPC812 / LPC832 flash tool

## Features

- GUI and command-line operation
- Erase, read, program and compare functions
- Automatically adds the required checksum to the firmware image
- Safe to use: does not allow to lock you out of ISP by default
- Info functions: reading of Part ID, UID, boot code version, etc
- Wait function: polls the LPC81x until the ISP becomes available
- Option to automatically run the firmware after flashing


![LPC81x-ISP-tool screenshot](lpc81x_isp-screenshot.png "LPC81x-ISP-tool screenshot")


## Info

This tool is compatible with Python 2.7 and 3.6+

The tool requires the following 3rd party python modules:
- py-serial [http://pyserial.sourceforge.net/](http://pyserial.sourceforge.net/)
- intelhex [https://launchpad.net/intelhex/](https://launchpad.net/intelhex/)


It is designed for command-line usage in a makefile, but also has a simplistic GUI for programming.

A Windows executable is in [lpc81x-isp-windows.zip](lpc81x-isp-windows-64bit.zip) so Windows users don't need to install Python and respetive modules.


## Usage

For programming a HEX file via GUI just launch the application without any command line arguments.

For programming a HEX file from the command line, use the following example:

```
lpc81x_isp.py --wait --flash <firmware.hex> --run --port <usb-to-serial>
```

If the LPC MCU is not in ISP mode yet, the tool will wait and periodically probe the chip. After flashing the firmware, it will execute it.

Run ``lcp81x_isp.py --help`` to see all available command line arguments.


## Py2exe info

How to build the Windows executable using py2exe:

```
python setup.py py2exe
```

Output is in the *dist/* directory

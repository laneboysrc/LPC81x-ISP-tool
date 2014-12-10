#!/usr/bin/env python
'''
Access the NXP LPC81x microcontroller via ISP boot code using a
serial port (UART).

The LPC81x devices contain a bootloader that allows certain device
functions such as reading IDs, and reading / erasing / writing of the
flash memory. This is referred to as "ISP" in the device documentation.

See "Chapter 22: LPC81x Flash ISP and IAP programming" of version
Rev. 1.6 of the LPC81x User manual (UM10601.pdf) for details.

This utility allows access to most of the ISP functions.

Required 3rd party modules:
    py-serial   http://sourceforge.net/projects/pyserial/
    intelhex    https://launchpad.net/intelhex/

'''

# Author: Werner Lane
#
# E-mail: laneboysrc@gmail.com
#
# Tested with Python version 2.7


# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org>

from __future__ import print_function
from __future__ import division

import sys
import argparse
import platform
import os
from time import sleep
from collections import Counter

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("Missing the py-serial module. Please install it from\n"
        "    http://sourceforge.net/projects/pyserial/\n")
    raw_input("Press Enter to terminate this window...")
    sys.exit(1)

try:
    from intelhex import IntelHex, HexRecordError
except ImportError:
    print("Missing the intelhex module. Please install it from\n"
        "    https://launchpad.net/intelhex/\n")
    raw_input("Press Enter to terminate this window...")
    sys.exit(1)


VERSION = "v1.3"

PLATFORM = platform.system()


# Code Read Protection (CRP) address and patterns
CRP_ADDRESS = 0x000002fc

# Prevents sampling of the ISP entry pin
NO_ISP = 0x4E697370

# Access to chip via the SWD pins is disabled; allow partial flash update
CRP1 = 0x12345678

# Access to chip via the SWD pins is disabled; most flash commands are disabled
CRP2 = 0x87654321

# Access to chip via the SWD pins is disabled; prevents sampling of the ISP
# entry pin
CRP3 = 0x43218765

# RAM start address we use for programming and the Go command. We use
# 0x10000300 because everything below may be locked by CRP.
RAM_BASE_ADDRESS = 0x10000000
RAM_ADDRESS = RAM_BASE_ADDRESS + 0x300

# The first 80 bytes are retained during reset. This is useful for debugging.
RAM_SURVIVORS = 0x50

FLASH_BASE_ADDRESS = 0x00000000
PAGE_SIZE = 64
SECTOR_SIZE = 1024


class ISPException(Exception):
    '''
    Custom exception that stores a message and the ISP return code
    '''

    def __init__(self, message, response=None):
        # Call the base class constructor with the parameters it needs
        Exception.__init__(self, message)

        # Custom code
        self.response = response


def open_isp(port, wait=False):
    '''
    Open the given serial port and synchronize with the ISP in the LPC81x.

    This function can handle multiple states the ISP may be in:

        - ISP has just started and we need to perform the whole synchonization
          sequence

        - ISP has already been synchronized (by a previous run of another
          application) and ECHO is off

        - ISP has already been synchronized and ECHO is on

    This function turns ECHO off and returns the serial object that can be
    used for issuing commands to the ISP.

    It raises ISPException() exception when things go wrong.
    '''
    try:
        # A timeout of 100 ms is enough unless we use a really slow baud rate
        # like 300
        uart = serial.Serial(port, 115200, timeout=0.1)
    except serial.SerialException as error:
        raise ISPException('ERROR: {}'.format(error))

    if wait:
        print("Waiting for LPC81x to enter ISP mode...")

    while True:
        uart.flush()
        uart.write(b"?")
        uart.flush()

        response = uart.readline()
        if response == b"Synchronized\r\n":
            uart.write(b"Synchronized\r\n")
            uart.flush()
            uart.readline()             # Discard echo

            response = uart.readline().decode("ASCII", errors="replace")
            if response != "OK\r\n":
                raise ISPException('ERROR: Expected "OK" after sending '
    		        '"Synchronized", but received "{}"'.format(response), response)

            # Send crystal frequency in kHz (always 12 MHz for the LPC81x)
            uart.write(b"12000\r\n")
            uart.flush()
            uart.readline()             # Discard echo

            response = uart.readline().decode("ASCII", errors="replace")
            if response != "OK\r\n":
                raise ISPException('ERROR: Expected "OK" after sending crystal '
    		        'frequency, but received "{}"'.format(response), response)

            uart.write(b"A 0\r\n")       # Turn ECHO off
            uart.flush()
            uart.readline()             # Discard (last) echo

            response = uart.readline().decode("ASCII", errors="replace")
            if response != "0\r\n":
                raise ISPException('ERROR: Expected "0" after turning ECHO '
                    'off, but received "{}"'.format(response), response)
            uart.timeout = 5
            return uart

        elif response == b"?":
            # We may already be in ISP mode, with ECHO being on.
            # We terminate with CR/LF, which should respond with "1\r\n" because
            # '?' is an invalid command.
            # We have to skip the ECHOed CR/LF though!
            uart.write(b"\r\n")
            uart.flush()
            uart.readline()             # Discard echo

            response = uart.readline().decode("ASCII", errors="replace")
            if response != "1\r\n":
                if not wait:
                    raise ISPException("ERROR: LPC81x not in ISP mode.")
            else:
                uart.write(b"A 0\r\n")       # Turn ECHO off
                uart.flush()
                uart.readline()             # Discard (last) echo

                response = uart.readline().decode("ASCII", errors="replace")
                if response != "0\r\n":
                    raise ISPException('ERROR: Expected "0" after turning ECHO '
                        'off, but received "{}"'.format(response), response)
                uart.timeout = 5
                return uart

        else:
            # We may already be in ISP mode, with ECHO being off.
            # We send a CR/LF, which should respond with "1\r\n" because
            # '?' is an invalid command.
            uart.write(b"\r\n")
            uart.flush()

            response = uart.readline().decode("ASCII", errors="replace")
            if response == "1\r\n":
                uart.timeout = 5
                return uart
            if not wait:
                raise ISPException("ERROR: LPC81x not in ISP mode.")

        sleep(0.3)


def send_command(uart, command):
    '''
    Send a command to the ISP and check that we receive and COMMAND_SUCCESS (0)
    response.

    Note that this function assumes that ECHO is turned off.
    '''

    uart.write((command + "\r\n").encode("ASCII"))
    uart.flush()
    response = uart.readline().decode("ASCII")
    if response != "0\r\n":
        raise ISPException('ERROR: Command "%s" failed. Return code: %s' %
            (command, response.strip()), response.strip())


def read_image_file(image_file):
    '''
    Read the given image file. First we try to read the file as Intel-hex, if
    that fails we assume it is a binary image.

    The file handle is closed before returning the IntelHex object containing
    the image data.
    '''

    hexfile = IntelHex()
    try:
        hexfile.fromfile(image_file, format='hex')

    except HexRecordError:
        # Not a valid HEX file, so assume we are dealing with a binary image
        image_file.seek(0)
        hexfile.fromfile(image_file, format='bin')

    image_file.close()
    return hexfile


def append_signature(hexfile):
    ''' Calculate the signature that the ISP uses to detect "valid code" '''

    signature = 0
    for vector in range(0, 7 * 4, 4):
        signature = signature + (
            (hexfile[vector + 3] << 24) +
            (hexfile[vector + 2] << 16) +
            (hexfile[vector + 1] << 8) +
            (hexfile[vector]))
    signature = (signature ^ 0xffffffff) + 1    # Two's complement

    vector8 = 28
    hexfile[vector8 + 3] = (signature >> 24) & 0xff
    hexfile[vector8 + 2] = (signature >> 16) & 0xff
    hexfile[vector8 + 1] = (signature >> 8) & 0xff
    hexfile[vector8] = signature& 0xff


def read_part_id(uart):
    '''
    Read the Part ID from the MCU and decode it in human readable form.
    '''
    known_parts = {
        0x00008100: "LPC810M021FN8",
        0x00008110: "LPC811M001JDH16",
        0x00008120: "LPC812M101JDH16",
        0x00008121: "LPC812M101JD20",
        0x00008122: "LPC812M101JDH20, LPC812M101JTB16"}

    send_command(uart, "J")
    part_id = int(uart.readline().strip(), 10)

    try:
        part_name = known_parts[part_id]
    except KeyError:
        part_name = "unknown"

    return part_id, part_name


def read_uid(uart):
    '''
    Read the Unique ID from the MCU.
    '''
    send_command(uart, "N")
    return [int(uart.readline().strip(), 10) for dummy in range(4)]


def read_boot_code_version(uart):
    '''
    Read the version number of the boot code from the MCU.
    '''
    send_command(uart, "K")
    return (uart.readline().decode("ASCII").strip(),
            uart.readline().decode("ASCII").strip())


def get_flash_size(uart):
    '''
    Obtain the size of the Flash memory from the LPC81x.
    If we are unable to identify the part we assume a default of 4 KBytes.
    '''
    known_parts = {
        0x00008100: 4 * 1024,       # LPC810M021FN8
        0x00008110: 8 * 1024,       # LPC811M001JDH16
        0x00008120: 16 * 1024,      # PC812M101JDH16
        0x00008121: 16 * 1024,      # LPC812M101JD20
        0x00008122: 16 * 1024}      # LPC812M101JDH20, LPC812M101JTB16

    part_id, _ = read_part_id(uart)

    try:
        return known_parts[part_id]
    except KeyError:
        print ("WARNING: Unknown part identification {:#010X}. " +
            "Using 4 KB as flash size.").format(part_id)
        return 4 * 1024


def dump_survivors(uart):
    '''
    Print a HEX dump of the first 80 bytes of RAM, which are preserved
    during reset and are useful for debugging.
    '''
    send_command(uart, "R {:d} {:d}".format(RAM_BASE_ADDRESS, RAM_SURVIVORS))
    ram_data = bytearray(uart.read(RAM_SURVIVORS))
    if len(ram_data) != RAM_SURVIVORS:
        raise ISPException(
            'ERROR: Failed to read the first {:d} bytes of RAM.' %
                RAM_SURVIVORS)

    bytes_per_row = 16
    address = 0

    while ram_data:
        row_data = ram_data[0:bytes_per_row]
        del ram_data[0:bytes_per_row]

        print("{:04X}  ".format(address), end='')
        for data_byte in row_data:
            print("{:02X}".format(data_byte), end='')
        print("  ", end='')

        string_representation = "".join(
            [chr(c) if (c >= 32 and c <= 127) else '.' for c in row_data])
        print("{:s}".format(string_representation))

        address = address + bytes_per_row


def read(uart, image_file):
    '''
    Read the contents of the whole flash memory and write it into a binary
    image file.
    '''
    flash_size = get_flash_size(uart)

    send_command(uart, "R {:d} {:d}".format(FLASH_BASE_ADDRESS, flash_size))
    image_data = uart.read(flash_size)
    if len(image_data) != flash_size:
        raise ISPException('ERROR: Failed to read the whole Flash memory')

    image_file.write(image_data)
    image_file.close()


def erase(uart):
    '''
    Erase all of the flash memory.
    '''

    flash_size = get_flash_size(uart)

    # Unlock the chip with the magic number
    send_command(uart, "U 23130")

    # Erase all sectors
    last_sector = (flash_size // SECTOR_SIZE) - 1
    send_command(uart, "P 0 {:d}".format(last_sector))
    send_command(uart, "E 0 {:d}".format(last_sector))


def program(uart, image_file, allow_code_protection=False, progress_cb=None):
    '''
    Write the given binary (or IntelHex) image file into the flash memory.

    The image is checked whether it contains any of the code protection
    values, and flashing is aborted (unless instructed with a flag)
    so that we don't "brick" the ISP functionality.

    Also the checksum of the vectors that the ISP uses to detect valid
    flash is generated and added to the image before flashing.

    If an IntelHex file is given, only the flash sectors were data is present
    in the image file are erased and programmed. This allows partial flashing,
    and preservation of persistent data between software upgrades.
    The --erase command can be used before programming to erase the whole
    flash memory.
    '''
    hexfile = read_image_file(image_file)
    used_sectors = sorted(Counter(
        address // SECTOR_SIZE for address in hexfile.addresses()).keys())


    # Ensure the image is not emtpy
    if hexfile.minaddr() == None:
        raise ISPException('ERROR: image file is empty')


    # Ensure the image fits into the flash
    flash_size = get_flash_size(uart)
    flash_size = 16384
    if hexfile.maxaddr() >= flash_size:
        raise ISPException('ERROR: image too large for the flash memory size')


    # Abort if the Code Read Protection in the image contains one of the
    # special patterns. We don't want to lock us out of the chip...
    if not allow_code_protection:
        pattern = ((hexfile[CRP_ADDRESS + 3] << 24) +
            (hexfile[CRP_ADDRESS + 2] << 16) +
            (hexfile[CRP_ADDRESS + 1] << 8) +
            hexfile[CRP_ADDRESS])

        if pattern == NO_ISP:
            raise ISPException(
                'ERROR: NO_ISP code read protection detected in image ' +
                'file')

        if pattern == CRP1:
            raise ISPException(
                'ERROR: CRP1 code read protection detected in image file')

        if pattern == CRP2:
            raise ISPException(
                'ERROR: CRP2 code read protection detected in image file')

        if pattern == CRP3:
            raise ISPException(
                'ERROR: CRP3 code read protection detected in image file')


    # Calculate the signature that the ISP uses to detect "valid code"
    append_signature(hexfile)


    # Unlock the chip with the magic number
    send_command(uart, "U 23130")


    # Program the image
    for index, sector in enumerate(used_sectors):
        if progress_cb is not None:
            progress_cb(float(index) / used_sectors.length())

        # Erase the sector
        send_command(uart, "P {sector:d} {sector:d}".format(sector=sector))
        send_command(uart, "E {sector:d} {sector:d}".format(sector=sector))

        address = sector * SECTOR_SIZE
        last_address = address + SECTOR_SIZE - 1

        send_command(uart, "W {:d} {:d}".format(RAM_ADDRESS, SECTOR_SIZE))
        uart.write(hexfile.tobinstr(start=address, end=last_address))
        send_command(uart, "P {sector:d} {sector:d}".format(sector=sector))
        send_command(uart, "C {:d} {:d} {:d}".format(
            address, RAM_ADDRESS, SECTOR_SIZE))

    return hexfile.maxaddr() - hexfile.minaddr() + 1


def compare(uart, image_file):
    '''
    Verify that the flash memory matches the given binary image.

    Returns True on match and False on mismatch.
    '''
    hexfile = read_image_file(image_file)
    used_pages = sorted(Counter(
        address // PAGE_SIZE for address in hexfile.addresses()).keys())

    append_signature(hexfile)

    for page in used_pages:
        address = page * PAGE_SIZE
        last_address = address + PAGE_SIZE - 1
        page_data = hexfile.tobinstr(start=address, end=last_address)
        send_command(uart, "W {:d} {:d}".format(RAM_ADDRESS, PAGE_SIZE))
        uart.write(page_data)
        try:
            send_command(uart, "M {:d} {:d} {:d}".format(
                address, RAM_ADDRESS, PAGE_SIZE))
        except ISPException as error:
            if error.response == "10":
                return False
            raise error
    return True


def reset_mcu(uart):
    '''
    Reset the MCU to start the application.
    We do that by downloading a small binary into RAM. This binary corresponds
    to the following C code:

        SCB->AIRCR = 0x05FA0004;

    This code resets the ARM CPU by setting SYSRESETREQ. We load this
    program into RAM and run it with the "Go" command.
    '''
    reset_program = bytearray((
        0x01, 0x4a, 0x02, 0x4b, 0x1a, 0x60, 0x70, 0x47,
        0x04, 0x00, 0xfa, 0x05, 0x0c, 0xed, 0x00, 0xe0))
    send_command(uart, "W {:d} {:d}".format(RAM_ADDRESS, len(reset_program)))
    uart.write(reset_program)
    uart.flush()

    # Unlock the Go command
    send_command(uart, "U 23130")

    # Run the program from RAM. Note that this command does not respond with
    # COMMAND_SUCCESS as it directly executes.
    uart.write("G {:d} T\r\n".format(RAM_ADDRESS).encode("ASCII"))
    uart.flush()


def parse_commandline():
    '''
    Parse command line arguments
    '''
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)

    info_group = parser.add_argument_group('Device information')
    read_group = parser.add_argument_group('Read and compare functions')
    write_group = parser.add_argument_group('Erase and write functions')
    run_group = parser.add_argument_group('Code execution functions')
    convenience_group = parser.add_argument_group('Convenience functions')

    parser.add_argument("-p", "--port",
        dest='port',
        default="/dev/ttyUSB0",
        help="serial port where the LPC81x is connected to. Defaults to "
            "/dev/ttyUSB0.")

    parser.add_argument("-v", "--version",
        dest='version',
        action='store_true',
        help="show the version number of this program and exit.")

    info_group.add_argument("-j", "-i", "--id", "--part-id",
        dest='part_id',
        action='store_true',
        help="identify which particular LPC81x chip is connected.")

    info_group.add_argument("-k", "-b", "--boot-code-version",
        dest='boot_code_version',
        action='store_true',
        help="display the boot code version.")

    info_group.add_argument("-n", "-u", "--uid",
        dest='uid',
        action='store_true',
        help="display the unique device ID.")

    read_group.add_argument("-s", "--survivors",
        dest='survivors',
        action='store_true',
        help=("dump the fist {:d} bytes of RAM, which are retained during "
            "reset").format(RAM_SURVIVORS))

    read_group.add_argument("-r", "--read",
        dest='read',
        metavar='image.bin',
        type=argparse.FileType('wb'),
        help="read the MCU flash memory into a binary image file.")

    read_group.add_argument("-c", "--compare",
        dest='compare',
        metavar='image.bin',
        type=argparse.FileType('rb'),
        help="compare a binary image with MCU flash memory.")

    write_group.add_argument("-e", "--erase",
        dest='erase',
        action='store_true',
        help="erase the MCUs flash memory.")

    write_group.add_argument("-f", "-w", "--flash", "--write", "--program",
        dest='program',
        metavar='image.bin',
        type=argparse.FileType('rb'),
        help="write a binary (or IntelHex) image to the MCU flash memory.")

    write_group.add_argument("--allow-code-protection",
        action='store_true',
        help="allow code protection. Only applies when flashing a new image. "
            "WARNING: this may potentially prevent using ISP after the next "
            "reset!")

    run_group.add_argument("-g", "--go", "--run",
        action='store_true',
        help="run the application by performing a system reset.")

    convenience_group.add_argument("--wait", "--ready",
        action='store_true',
        help="wait unit ISP becomes ready. If not specified the program will "
        "terminate immediately when the LPC81x is not in ISP mode.")

    args = parser.parse_args()

    return args


###############################################################################
def gui(args):
    ''' Run the programmer with a GUI '''
    import Tkinter as tk
    import ttk
    import tkFileDialog

    class Gui(ttk.Frame):
        ''' Programmer graphical user interface '''

        def __init__(self, master=None):
            ttk.Frame.__init__(self, master)

            self.root = master
            self.root.title("LPC81x programmer")


            # Widget variables
            self.firmware_image = tk.StringVar()
            self.port = tk.StringVar()
            self.progress = tk.StringVar()


            # Create the firmware selection frame
            self.frm_firmware = ttk.LabelFrame(self, text="Firmware .hex file:")
            self.lbl_filename = ttk.Label(self.frm_firmware,
                textvariable=self.firmware_image)
            self.btn_open = ttk.Button(self.frm_firmware, text="Select file...",
                command=self.select_hex_file)


            # Create the serial port selection frame
            self.frm_port = ttk.LabelFrame(self, text="Serial port:")
            self.cb_port = ttk.Combobox(self.frm_port, textvariable=self.port)


            # Create the programming frame
            self.frm_program = ttk.LabelFrame(self, text="Program:")
            self.progressbar = ttk.Progressbar(self.frm_program, length=200,
                orient=tk.HORIZONTAL, mode='determinate',
                variable=self.progress)
            self.btn_program = ttk.Button(self.frm_program, text="Program",
                state=tk.DISABLED, command=self.program)
            self.frm_messages = ttk.Frame(self.frm_program)
            self.lbl_messages = tk.Text(self.frm_messages, height=5, width=60,
                state=tk.DISABLED)
            self.scr_messages = ttk.Scrollbar(self.frm_messages,
                orient=tk.VERTICAL, command=self.lbl_messages.yview)
            self.lbl_messages.config(yscrollcommand=self.scr_messages.set)


            # Place all items in the grid
            self.config(padding=(10, 10, 10, 10))
            self.grid(row=0, column=0, sticky="nsew")

            self.frm_firmware.grid(column=0, row=0, sticky="we")
            self.frm_firmware.config(padding=(5, 0, 5, 5))
            self.lbl_filename.grid(column=0, row=0, sticky="we")
            self.btn_open.grid(column=1, row=0)

            self.frm_port.grid(column=0, row=1, sticky="we", pady=10)
            self.frm_port.config(padding=(5, 0, 5, 5))
            self.cb_port.grid(column=0, row=0)

            self.frm_program.grid(column=0, row=2, sticky="nsew")
            self.progressbar.grid(column=0, row=0, sticky="we", padx=5)
            self.btn_program.grid(column=1, row=0, padx=5, pady=5)
            self.frm_messages.grid(column=0, row=1, columnspan=2, sticky="nsew",
                padx=5, pady=5)
            self.lbl_messages.grid(column=0, row=0, sticky="nsew")
            self.scr_messages.grid(column=1, row=0, sticky="ns")


            # Configure resize weights
            self.root.columnconfigure(0, weight=1)
            self.root.rowconfigure(0, weight=1)
            self.columnconfigure(0, weight=1)
            self.rowconfigure(2, weight=1)
            self.frm_firmware.columnconfigure(0, weight=1)
            self.frm_firmware.rowconfigure(0, weight=1)
            self.frm_program.columnconfigure(0, weight=1)
            self.frm_program.rowconfigure(1, weight=1)
            self.frm_messages.columnconfigure(0, weight=1)
            self.frm_messages.rowconfigure(0, weight=1)


            # Set default values
            self.firmware_image.set("(no file selected)")
            self.progress.set(0)


            self.add_message("LPC81x programmer successfully launched.")
            self.root.after(1, self.check_ports)


        def check_ports(self):
            '''
            Background task to populate the combo box with available serial
            ports.

            On Linux and Mac OS we use our own function, filtering USB-serial
            dongles on Windows and using call-out devices on Mac OS.

            For other platforms we use the function provided by py-serial
            '''
            serial_ports = []

            if PLATFORM == 'Linux' or PLATFORM == 'Darwin':
                path = "/dev/"
                prefix = "ttyUSB"
                if PLATFORM == "Darwin":
                    prefix = "cu."

                for filename in os.listdir(path):
                    filepath = os.path.join(path, filename)
                    if filename.startswith(prefix):
                        serial_ports.append(filepath)

            else:
                for port, _, _ in sorted(serial.tools.list_ports.comports()):
                    serial_ports.append(port)

            self.cb_port.config(values=serial_ports)
            if serial_ports and self.port.get() == "":
                self.port.set(serial_ports[0])

            self.root.after(1000, self.check_ports)


        def select_hex_file(self):
            ''' Let the user interactively select the hex file '''
            fname = tkFileDialog.askopenfilename(filetypes=(
                ("Firmware image files", "*.hex"),
                ("All files", "*.*")))

            if fname:
                self.firmware_image.set(fname)
                self.btn_program["state"] = tk.NORMAL
                self.btn_program.focus()


        def add_message(self, message):
            '''
            Add the given message to the log window and ensure it is seen
            '''
            self.lbl_messages.config(state=tk.NORMAL)
            self.lbl_messages.insert('end', message + "\n")
            self.lbl_messages.config(state=tk.DISABLED)
            self.lbl_messages.see('end')


        def progress_callback(self, percent):
            ''' Callback function to update the progress bar '''
            self.progress.set(percent * 100)


        def program(self):
            ''' Program the selected firmware image '''
            with open(self.firmware_image.get()) as image_file:
                try:
                    uart = open_isp(self.port.get())

                    self.add_message("Programming ...")
                    program(uart, image_file,
                        progress_cb=self.progress_callback)

                    self.add_message("Starting the program...")
                    reset_mcu(uart)
                    self.add_message("Done.")
                    uart.close()

                except ISPException as error:
                    self.add_message(str(error))


    app = Gui(master=tk.Tk())
    app.mainloop()


###############################################################################
def main():
    '''
    Program the NXP LPC81x microcontrollers using ISP
    '''
    args = parse_commandline()

    # Create a duplicate of the parsed args. Check if any flag is given
    # (except --port). If none given launch the GUI.
    commands = dict(vars(args))
    del commands['port']
    if not any(commands.values()):
        gui(args)
        sys.exit(0)


    if args.version:
        print(VERSION)
        sys.exit(0)

    try:
        uart = open_isp(args.port, args.wait)

        if args.part_id:
            part_id, part_name = read_part_id(uart)
            print("Part ID: {:#010X} ({})".format(part_id, part_name))

        if args.boot_code_version:
            minor, major = read_boot_code_version(uart)
            print("Boot code version: v{0}.{1}".format(major, minor))

        if args.uid:
            uid = read_uid(uart)
            print("UID: {0:08X} {1:08X} {2:08X} {3:08X}".format(*uid))

        if args.survivors:
            dump_survivors(uart)

        if args.read:
            print("Reading flash contents ...")
            read(uart, args.read)
            print("Done.")

        if args.compare:
            print("Comparing ...")
            if compare(uart, args.compare):
                print("Image matches MCU content.")
            else:
                print("ERROR: Image does NOT match MCU content!")

        if args.erase:
            print("Erasing flash memory ...")
            erase(uart)
            print("Done.")

        if args.program:
            print("Programming ...")
            bytes_written = program(uart, args.program,
                args.allow_code_protection)
            print("Wrote {:d} bytes.".format(bytes_written))

        if args.go:
            reset_mcu(uart)
            sys.exit(0)

    except ISPException as error:
        print(error)
        sys.exit(1)


if __name__ == '__main__':
    main()

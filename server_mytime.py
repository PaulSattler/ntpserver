import datetime
import socket
import struct
import time
import queue
import threading
import select
import msvcrt  # Für Windows-Tastatureingaben
import ctypes

# Windows-spezifische Farben
STD_OUTPUT_HANDLE = -11
std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

def set_color(color):
    """Setzt die Konsolenfarbe (0-15)"""
    ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, color)

# Farben
RED = 12  # Rot
WHITE = 7  # Weiß

# Zeiteingabe in Minuten
print(f"Bitte geben Sie die Zeit in Minuten ein, die abgezogen werden soll: ")
time_offset_minutes = float(input())
TIME_OFFSET = time_offset_minutes * 60  # Umrechnung in Sekunden

taskQueue = queue.Queue()
stopFlag = False

def get_terminal_width():
    """Gibt die aktuelle Breite des Terminals zurück"""
    try:
        columns, _ = shutil.get_terminal_size()
        return columns
    except:
        return 80  # Standardbreite falls nicht ermittelbar

def format_status_line(ip, port, status, current_time, offset):
    """Formatiert die Statuszeile mit der aktuellen Terminalbreite"""
    width = get_terminal_width()
    base_text = f"IP: {ip} | Port: {port} | Status: {status} | NTP Time: {current_time} | Offset: -{offset} min"
    
    # Wenn die Zeile zu lang ist, kürzen wir sie
    if len(base_text) > width - 1:
        # Wir behalten die wichtigsten Informationen
        time_info = f"NTP Time: {current_time}"
        offset_info = f"Offset: -{offset} min"
        # Berechne die verfügbare Länge für die IP/Port/Status Information
        available_length = width - len(time_info) - len(offset_info) - 5  # 5 für die Trennzeichen
        status_info = f"IP: {ip} | Port: {port} | Status: {status}"
        if len(status_info) > available_length:
            # Kürze die IP-Adresse
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                ip = f"{ip_parts[0]}...{ip_parts[3]}"
            status_info = f"IP: {ip} | Port: {port} | Status: {status}"
        
        return f"{status_info} | {time_info} | {offset_info}"
    return base_text

def update_time_offset():
    global time_offset_minutes, TIME_OFFSET
    print(f"Bitte geben Sie den neuen Zeitoffset in Minuten ein: ")
    try:
        new_offset = float(input())
        time_offset_minutes = new_offset
        TIME_OFFSET = time_offset_minutes * 60
        print(f"Zeitoffset wurde auf {time_offset_minutes} Minuten aktualisiert")
    except ValueError:
        print(f"Ungültige Eingabe. Zeitoffset wurde nicht geändert.")

def system_to_ntp_time(timestamp):
    """Convert a system time to a NTP time.

    Parameters:
    timestamp -- timestamp in system time

    Returns:
    corresponding NTP time
    """
    # Ziehe das Zeitoffset ab
    return (timestamp - TIME_OFFSET) + NTP.NTP_DELTA

def _to_int(timestamp):
    """Return the integral part of a timestamp.

    Parameters:
    timestamp -- NTP timestamp

    Retuns:
    integral part
    """
    return int(timestamp)

def _to_frac(timestamp, n=32):
    """Return the fractional part of a timestamp.

    Parameters:
    timestamp -- NTP timestamp
    n         -- number of bits of the fractional part

    Retuns:
    fractional part
    """
    return int(abs(timestamp - _to_int(timestamp)) * 2**n)

def _to_time(integ, frac, n=32):
    """Return a timestamp from an integral and fractional part.

    Parameters:
    integ -- integral part
    frac  -- fractional part
    n     -- number of bits of the fractional part

    Retuns:
    timestamp
    """
    return integ + float(frac)/2**n	
		


class NTPException(Exception):
    """Exception raised by this module."""
    pass


class NTP:
    """Helper class defining constants."""

    _SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
    """system epoch"""
    _NTP_EPOCH = datetime.date(1900, 1, 1)
    """NTP epoch"""
    NTP_DELTA = (_SYSTEM_EPOCH - _NTP_EPOCH).days * 24 * 3600
    """delta between system and NTP time"""

    REF_ID_TABLE = {
            'DNC': "DNC routing protocol",
            'NIST': "NIST public modem",
            'TSP': "TSP time protocol",
            'DTS': "Digital Time Service",
            'ATOM': "Atomic clock (calibrated)",
            'VLF': "VLF radio (OMEGA, etc)",
            'callsign': "Generic radio",
            'LORC': "LORAN-C radionavidation",
            'GOES': "GOES UHF environment satellite",
            'GPS': "GPS UHF satellite positioning",
    }
    """reference identifier table"""

    STRATUM_TABLE = {
        0: "unspecified",
        1: "primary reference",
    }
    """stratum table"""

    MODE_TABLE = {
        0: "unspecified",
        1: "symmetric active",
        2: "symmetric passive",
        3: "client",
        4: "server",
        5: "broadcast",
        6: "reserved for NTP control messages",
        7: "reserved for private use",
    }
    """mode table"""

    LEAP_TABLE = {
        0: "no warning",
        1: "last minute has 61 seconds",
        2: "last minute has 59 seconds",
        3: "alarm condition (clock not synchronized)",
    }
    """leap indicator table"""

class NTPPacket:
    """NTP packet class.

    This represents an NTP packet.
    """
    
    _PACKET_FORMAT = "!B B B b 11I"
    """packet format to pack/unpack"""

    def __init__(self, version=2, mode=3, tx_timestamp=0):
        """Constructor.

        Parameters:
        version      -- NTP version
        mode         -- packet mode (client, server)
        tx_timestamp -- packet transmit timestamp
        """
        self.leap = 0
        """leap second indicator"""
        self.version = version
        """version"""
        self.mode = mode
        """mode"""
        self.stratum = 0
        """stratum"""
        self.poll = 0
        """poll interval"""
        self.precision = 0
        """precision"""
        self.root_delay = 0
        """root delay"""
        self.root_dispersion = 0
        """root dispersion"""
        self.ref_id = 0
        """reference clock identifier"""
        self.ref_timestamp = 0
        """reference timestamp"""
        self.orig_timestamp = 0
        self.orig_timestamp_high = 0
        self.orig_timestamp_low = 0
        """originate timestamp"""
        self.recv_timestamp = 0
        """receive timestamp"""
        self.tx_timestamp = tx_timestamp
        self.tx_timestamp_high = 0
        self.tx_timestamp_low = 0
        """tansmit timestamp"""
        
    def to_data(self):
        """Convert this NTPPacket to a buffer that can be sent over a socket.

        Returns:
        buffer representing this packet

        Raises:
        NTPException -- in case of invalid field
        """
        try:
            packed = struct.pack(NTPPacket._PACKET_FORMAT,
                (self.leap << 6 | self.version << 3 | self.mode),
                self.stratum,
                self.poll,
                self.precision,
                _to_int(self.root_delay) << 16 | _to_frac(self.root_delay, 16),
                _to_int(self.root_dispersion) << 16 |
                _to_frac(self.root_dispersion, 16),
                self.ref_id,
                _to_int(self.ref_timestamp),
                _to_frac(self.ref_timestamp),
                #Change by lichen, avoid loss of precision
                self.orig_timestamp_high,
                self.orig_timestamp_low,
                _to_int(self.recv_timestamp),
                _to_frac(self.recv_timestamp),
                _to_int(self.tx_timestamp),
                _to_frac(self.tx_timestamp))
        except struct.error:
            raise NTPException("Invalid NTP packet fields.")
        return packed

    def from_data(self, data):
        """Populate this instance from a NTP packet payload received from
        the network.

        Parameters:
        data -- buffer payload

        Raises:
        NTPException -- in case of invalid packet format
        """
        try:
            unpacked = struct.unpack(NTPPacket._PACKET_FORMAT,
                    data[0:struct.calcsize(NTPPacket._PACKET_FORMAT)])
        except struct.error:
            raise NTPException("Invalid NTP packet.")

        self.leap = unpacked[0] >> 6 & 0x3
        self.version = unpacked[0] >> 3 & 0x7
        self.mode = unpacked[0] & 0x7
        self.stratum = unpacked[1]
        self.poll = unpacked[2]
        self.precision = unpacked[3]
        self.root_delay = float(unpacked[4])/2**16
        self.root_dispersion = float(unpacked[5])/2**16
        self.ref_id = unpacked[6]
        self.ref_timestamp = _to_time(unpacked[7], unpacked[8])
        self.orig_timestamp = _to_time(unpacked[9], unpacked[10])
        self.orig_timestamp_high = unpacked[9]
        self.orig_timestamp_low = unpacked[10]
        self.recv_timestamp = _to_time(unpacked[11], unpacked[12])
        self.tx_timestamp = _to_time(unpacked[13], unpacked[14])
        self.tx_timestamp_high = unpacked[13]
        self.tx_timestamp_low = unpacked[14]

    def GetTxTimeStamp(self):
        return (self.tx_timestamp_high,self.tx_timestamp_low)

    def SetOriginTimeStamp(self,high,low):
        self.orig_timestamp_high = high
        self.orig_timestamp_low = low
        

class RecvThread(threading.Thread):
    def __init__(self,socket):
        threading.Thread.__init__(self)
        self.socket = socket
    def run(self):
        global taskQueue,stopFlag
        while True:
            if stopFlag == True:
                print(f"RecvThread Ended")
                break
            rlist,wlist,elist = select.select([self.socket],[],[],1)
            if len(rlist) != 0:
                for tempSocket in rlist:
                    try:
                        data,addr = tempSocket.recvfrom(1024)
                        set_color(RED)
                        print(f"Received packet from {addr[0]}:{addr[1]}")
                        set_color(WHITE)
                        recvTimestamp = system_to_ntp_time(time.time())
                        taskQueue.put((data,addr,recvTimestamp))
                    except (ConnectionResetError, OSError) as msg:
                        print(f"Socket error: {msg}")
                        continue

class WorkThread(threading.Thread):
    def __init__(self,socket):
        threading.Thread.__init__(self)
        self.socket = socket
    def run(self):
        global taskQueue,stopFlag
        while True:
            if stopFlag == True:
                print(f"WorkThread Ended")
                break
            try:
                data,addr,recvTimestamp = taskQueue.get(timeout=1)
                recvPacket = NTPPacket()
                recvPacket.from_data(data)
                timeStamp_high,timeStamp_low = recvPacket.GetTxTimeStamp()
                sendPacket = NTPPacket(version=3,mode=4)
                sendPacket.stratum = 2
                sendPacket.poll = 10
                sendPacket.ref_timestamp = recvTimestamp-5
                sendPacket.SetOriginTimeStamp(timeStamp_high,timeStamp_low)
                sendPacket.recv_timestamp = recvTimestamp
                sendPacket.tx_timestamp = system_to_ntp_time(time.time())
                socket.sendto(sendPacket.to_data(),addr)
                set_color(RED)
                print(f"Sended to {addr[0]}:{addr[1]}")
                set_color(WHITE)
            except queue.Empty:
                continue
                
        
listenIp = "0.0.0.0"
listenPort = 123
socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
socket.bind((listenIp,listenPort))
print(f"Local socket: {socket.getsockname()}")
recvThread = RecvThread(socket)
recvThread.start()
workThread = WorkThread(socket)
workThread.start()

while True:
    try:
        # Prüfe auf Tastatureingabe
        if msvcrt.kbhit():
            key = msvcrt.getch().decode('utf-8').lower()
            if key == 't':
                update_time_offset()
        
        ntp_time = system_to_ntp_time(time.time())
        # Konvertiere NTP-Zeit zurück in lesbares Format
        ntp_seconds = ntp_time - NTP.NTP_DELTA
        current_time = datetime.datetime.fromtimestamp(ntp_seconds).strftime("%Y-%m-%d %H:%M:%S")
        status = "RUNNING" if not stopFlag else "STOPPED"
        print(f"IP: {listenIp} | Port: {listenPort} | Status: {status} | NTP Time: {current_time} | Offset: -{time_offset_minutes} min")
        time.sleep(1)
    except KeyboardInterrupt:
        print(f"Exiting...")
        stopFlag = True
        recvThread.join()
        workThread.join()
        print(f"Exited")
        break
        
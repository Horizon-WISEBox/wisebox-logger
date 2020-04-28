#!/usr/bin/env python3.7

import ctypes
import os
import struct
import sys

from datetime import datetime, timedelta
from pathlib import Path

from jsonargparse import ArgumentParser, ActionConfigFile

from scapy.all import sniff

import pytz

import RPi.GPIO as GPIO


DESCRIPTION = '802.11 probe request frame logger'
VERSION = 2.0

__ENCODING = 'utf-8'


class Interface():

    def __init__(self):
        self.__so = ctypes.CDLL('libnexio.so')
        self.__nexio = self.__so.nex_init_netlink()

    def get_chanspec(self):
        GET_CHANSPEC = 262
        b = ctypes.create_string_buffer(b'chanspec')
        self.__so.nex_ioctl(self.__nexio, GET_CHANSPEC, b, 9, False)
        return struct.unpack_from('H', b.raw)[0]

    def get_channel(self):
        return self.get_chanspec() & 0xFF

    def set_channel(self, channel: int):
        SET_CHANSPEC = 263
        current = self.get_chanspec()
        chanspec = (current >> 8 << 8) | channel
        buf = bytearray(b'chanspec\x00\x00\x00\x00\x00')
        struct.pack_into('I', buf, 9, chanspec)
        b = ctypes.create_string_buffer(bytes(buf))
        self.__so.nex_ioctl(self.__nexio, SET_CHANSPEC, b, 13, True)

    def get_monitor_mode(self):
        GET_MONITOR = 107
        b = ctypes.create_string_buffer(4)
        self.__so.nex_ioctl(self.__nexio, GET_MONITOR, b, 4, False)
        return struct.unpack_from('B', b.raw)[0]

    def set_monitor_mode(self, mode: int):
        SET_MONITOR = 108
        buf = bytearray(b'\x00\x00\x00\x00')
        struct.pack_into('B', buf, 0, mode)
        b = ctypes.create_string_buffer(bytes(buf))
        self.__so.nex_ioctl(self.__nexio, SET_MONITOR, b, 4, True)


class Bucket():

    def __init__(self, starttime: datetime, interval: timedelta):
        self.__starttime = starttime
        self.__interval = interval
        self.__endtime = starttime + interval
        self.__elements = set()

    def add(self, mac: str):
        self.__elements.add(mac)

    def size(self):
        return len(self.__elements)

    def should_close(self, timestamp: datetime):
        return timestamp >= self.__endtime

    def find_bucket_for(self, timestamp: datetime):
        if timestamp < self.__endtime:
            raise Exception('timestamp must be after this bucket\'s end time')
        start = self.__starttime
        while True:
            start += self.__interval
            if (start + self.__interval) > timestamp:
                return Bucket(start, self.__interval)

    def __str__(self):
        return f'{self.__starttime}<{self.__interval}>: {len(self.__elements)}'

    def get_bytes(self):
        return struct.pack(
            '<iH',
            int(self.__starttime.timestamp()),
            len(self.__elements))


class FileWriter():

    def __init__(self, log_dir: str, starttime: datetime, interval: timedelta):
        self.__log_dir = log_dir
        self.__starttime = starttime
        self.__interval = interval
        self.__endtime = starttime + interval
        os.makedirs(log_dir, exist_ok=True)
        start = starttime.astimezone(pytz.UTC).strftime('%Y%m%d%H%M%S')
        self.__path = Path(log_dir, f'log.{start}.part')
        self.__file = self.__path.open(mode='wb', buffering=0)

    def should_rollover(self, timestamp: datetime):
        return timestamp >= self.__endtime

    def close(self):
        if not self.__file.closed:
            self.__file.close()
        self.__path.rename(str(self.__path).replace('.part', ''))

    def write(self, bucket: Bucket):
        if self.__file.closed:
            self.__file = self.__path.open(mode='wb', buffering=0)
        self.__file.write(bucket.get_bytes())

    def find_writer_for(self, timestamp: datetime):
        if timestamp < self.__endtime:
            raise Exception(
                'timestamp must be after this file writer\'s end time')
        start = self.__starttime
        while True:
            start += self.__interval
            if (start + self.__interval) > timestamp:
                return FileWriter(self.__log_dir, start, self.__interval)


class WiseParksLogger():

    def __init__(self, config, starttime: datetime):
        self.__config = config
        self.__bucket = Bucket(starttime, timedelta(
            minutes=config.bucket.interval))
        self.__filewriter = FileWriter(
            config.log.dir,
            starttime,
            timedelta(minutes=config.log.rollover.time))

        if config.activity.gpio.pin < 0:
            self.activity_start = lambda: ()
            self.activity_end = lambda: ()
        else:
            pin = config.activity.gpio.pin
            GPIO.setmode(GPIO.BOARD)
            GPIO.setup(pin, GPIO.OUT, initial=GPIO.LOW)
            self.activity_start = lambda: GPIO.output(pin, GPIO.HIGH)
            self.activity_end = lambda: GPIO.output(pin, GPIO.LOW)

    def write(self, timestamp: datetime):
        if self.__filewriter.should_rollover(timestamp):
            self.__filewriter.close()
            self.__filewriter = self.__filewriter.find_writer_for(timestamp)
        print(self.__bucket)
        self.__filewriter.write(self.__bucket)

    def log(self, timestamp: datetime, mac: str, rssi: int):
        self.activity_start()
        if rssi >= self.__config.filters.rssi.min:
            if self.__bucket.should_close(timestamp):
                self.write(timestamp)
                self.__bucket = self.__bucket.find_bucket_for(timestamp)
            self.__bucket.add(mac)
        self.activity_end()


def build_packet_callback(logger: WiseParksLogger):
    def packet_callback(packet):
        logger.log(
            datetime.fromtimestamp(packet.time),
            packet.addr2,
            abs(packet.dBm_AntSignal))
    return packet_callback


def main():
    app = Path(sys.argv[0]).stem

    parser = ArgumentParser(
        prog=app,
        default_config_files=[],
        description=DESCRIPTION,
        error_handler='usage_and_exit_error_handler')

    parser.add_argument(
        'interface',
        type=str,
        help='capture interface, e.g. wlan0')
    parser.add_argument(
        'channel',
        type=int,
        help='channel number to listen on')
    parser.add_argument(
        'log.dir',
        type=str,
        help='directory to write logs to')
    parser.add_argument(
        '--bucket.interval',
        type=int,
        default=5,
        help="bucket interval time in minutes (default: 5)")
    parser.add_argument(
        '--log.rollover.time',
        type=int,
        default=60,
        help='time, in minutes, between log file rollover (default: 60)')
    parser.add_argument(
        '--filters.rssi.min',
        type=abs,
        default=0,
        help='minimum (absolute) RSSI to log (default: 0)')
    parser.add_argument(
        '--activity.gpio.pin',
        type=int,
        default=-1,
        help='GPIO pin to signal activity on (default: unset)')
    parser.add_argument('--config', action=ActionConfigFile)
    parser.add_argument(
        '--version',
        action='version',
        version=f'{app} version {VERSION}')

    cfg = parser.parse_args()
    interface = Interface()
    interface.set_monitor_mode(2)
    interface.set_channel(cfg.channel)
    logger = WiseParksLogger(cfg, datetime.now())
    packet_cb = build_packet_callback(logger)
    sniff(iface=cfg.interface, prn=packet_cb,
          store=0, filter='type mgt subtype probe-req')
    GPIO.cleanup()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3.7

import ctypes
import io
import json
import os
import signal
import struct
import sys
from datetime import datetime, timedelta
from pathlib import Path

import netifaces
import pytz
import tzlocal
from jsonargparse import ActionConfigFile, ArgumentParser
from scapy.all import sniff

DESCRIPTION = '802.11 probe request frame logger'
VERSION = '1.0.0'
API_VERSION = 1
LOGFILE_VERSION = 1


class Header():

    def __init__(self, mac: str, config: object, timezone: str):
        ENCODING = 'utf_8'
        buf = io.BytesIO()
        buf.write(struct.pack('<H', LOGFILE_VERSION))
        for x in mac.split(':'):
            buf.write(struct.pack('<B', int(x, base=16)))
        buf.write(struct.pack('<I', config.bucket.interval))
        tz = timezone.encode(ENCODING)
        buf.write(struct.pack('<B', len(tz)))
        buf.write(tz)
        metadata = json.dumps({
            'filters.rssi.min': config.filters.rssi.min
        }).encode(ENCODING)
        buf.write(struct.pack('<I', len(metadata)))
        buf.write(metadata)
        self.__bytes = buf.getvalue()

    def get_bytes(self):
        return self.__bytes


class Bucket():

    def __init__(self, starttime: datetime, interval: timedelta):
        self.__starttime = starttime
        self.__interval = interval
        self.__endtime = starttime + interval
        self.__elements = dict()
        self.__frequency = 0

    def add(self, mac: str, rssi: int, frequency: int):
        if mac not in self.__elements or rssi > self.__elements[mac]:
            self.__elements[mac] = rssi
            self.__frequency = frequency

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
        count = len(self.__elements)
        buf = bytearray(8 + count)
        struct.pack_into(
            '<iHH',
            buf,
            0,
            int(self.__starttime.timestamp()),
            self.__frequency,
            count)
        i = 8
        for rssi in self.__elements.values():
            struct.pack_into('<b', buf, i, rssi)
            i += 1
        return bytes(buf)


class FileWriter():

    def __init__(
            self,
            log_dir: str,
            starttime: datetime,
            interval: timedelta,
            header: Header):
        self.__log_dir = log_dir
        self.__starttime = starttime
        self.__interval = interval
        self.__header = header
        self.__endtime = starttime + interval
        os.makedirs(log_dir, exist_ok=True)
        start = starttime.astimezone(pytz.UTC).strftime('%Y%m%d%H%M%S')
        self.__path = Path(log_dir, f'wp{start}.part')
        self.__file = self.__path.open(mode='wb', buffering=0)
        self.__file.write(header.get_bytes())

    def should_rollover(self, timestamp: datetime):
        return timestamp >= self.__endtime

    def close(self):
        if not self.__file.closed:
            self.__file.close()
        self.__path.rename(self.__path.with_suffix('.complete'))

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
                return FileWriter(
                    self.__log_dir, start, self.__interval, self.__header)


class WiseParksLogger():

    def __init__(
            self,
            config,
            starttime: datetime,
            mac: str,
            timezone: datetime.tzinfo):
        self.__config = config
        self.__bucket = Bucket(starttime, timedelta(
            minutes=config.bucket.interval))
        header = Header(mac, config, str(timezone))
        self.__filewriter = FileWriter(
            config.log.dir,
            starttime,
            timedelta(minutes=config.log.rollover.time),
            header)

    def write(self, timestamp: datetime):
        if self.__filewriter.should_rollover(timestamp):
            self.__filewriter.close()
            self.__filewriter = self.__filewriter.find_writer_for(timestamp)
        self.__filewriter.write(self.__bucket)

    def log(self, timestamp: datetime, mac: str, rssi: int, frequency: int):
        if self.__bucket.should_close(timestamp):
            self.write(timestamp)
            self.__bucket = self.__bucket.find_bucket_for(timestamp)
        if (self.__config.filters.rssi.min is None or
                rssi >= self.__config.filters.rssi.min):
            self.__bucket.add(mac, rssi, frequency)

    def close(self):
        self.__filewriter.close()


def build_packet_callback(logger: WiseParksLogger):
    def packet_callback(packet):
        try:
            freq = packet.ChannelFrequency
        except:
            freq = None
        if not freq or freq < 0:
            freq = 0
        logger.log(
            datetime.fromtimestamp(packet.time, tz=pytz.UTC),
            packet.addr2,
            packet.dBm_AntSignal,
            freq)
    return packet_callback


def find_incomplete_logs(config):
    d = Path(config.log.dir)
    if d.exists() and d.is_dir():
        for f in d.glob('*.part'):
            f.rename(f.with_suffix('.complete'))


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
        help='bucket interval time in minutes (default: 5)')
    parser.add_argument(
        '--log.rollover.time',
        type=int,
        default=60,
        help='time, in minutes, between log file rollover (default: 60)')
    parser.add_argument(
        '--filters.rssi.min',
        type=int,
        help='RSSI minimum filter level (default: off)')
    parser.add_argument('--config', action=ActionConfigFile)
    parser.add_argument(
        '--version',
        action='version',
        version=f'{app} version {VERSION}')

    cfg = parser.parse_args()

    startup_tasks = [find_incomplete_logs]
    for task in startup_tasks:
        task(cfg)

    try:
        iface = netifaces.ifaddresses(cfg.interface)
        mac = iface[netifaces.AF_LINK][0]['addr']
    except KeyError:
        mac = '00:00:00:00:00:00'
    logger = WiseParksLogger(
        cfg, datetime.now(tz=pytz.UTC), mac, tzlocal.get_localzone())

    def handler(signum, frame):
        logger.close()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, handler)
    packet_cb = build_packet_callback(logger)
    sniff(iface=cfg.interface, prn=packet_cb,
          store=0, filter='type mgt subtype probe-req')
    logger.close()


if __name__ == '__main__':
    main()

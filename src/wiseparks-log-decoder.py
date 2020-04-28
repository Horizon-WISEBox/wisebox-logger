import datetime
import struct
import sys


with open(sys.argv[1], 'rb') as f:
    i = struct.iter_unpack('<iH', f.read())
    for (a, b) in i:
        st = datetime.datetime.fromtimestamp(a)
        print(f'{st}, {b}')

import datetime
import struct
import sys


with open(sys.argv[1], 'rb') as f:
    buf = f.read()
i = 0
while i < len(buf):
    (a, b) = struct.unpack_from('<iH', buf, i)
    st = datetime.datetime.fromtimestamp(a, tz=datetime.timezone.utc)
    i += 6
    j = i + b
    rssis = []
    while i < j:
        (rssi, ) = struct.unpack_from('<b', buf, i)
        i += 1
        rssis.append(rssi)
    print(f'{st}, {b}, {rssis}')

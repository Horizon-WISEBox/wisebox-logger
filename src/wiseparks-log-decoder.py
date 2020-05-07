import datetime
import struct
import sys

import pytz

__ENCODING = 'utf_8'

with open(sys.argv[1], 'rb') as f:
    buf = f.read()

i = 0

print('HEADER')
print('======')

mac_bytes = struct.unpack_from('<BBBBBB', buf, i)
i += 6
print('MAC: {}'.format(':'.join([f'{x:02x}' for x in mac_bytes])))

channel = struct.unpack_from('<B', buf, i)[0]
i += 1
print(f'Channel: {channel}')

interval = struct.unpack_from('<I', buf, i)[0]
i += 4
print(f'Interval: {interval} minutes')

tz_len = struct.unpack_from('<B', buf, i)[0]
i += 1
timezone = buf[i:i+tz_len].decode(__ENCODING)
i += tz_len
print(f'Timezone: {timezone}')

metadata_len = struct.unpack_from('<I', buf, i)[0]
i += 4
metadata = buf[i:i+metadata_len].decode(__ENCODING)
i += metadata_len
print('Metadata:')
print(metadata)

print('RECORDS')
print('=======')
while i < len(buf):
    (a, b) = struct.unpack_from('<iH', buf, i)
    st = datetime.datetime.fromtimestamp(a, tz=pytz.UTC)
    i += 6
    j = i + b
    rssis = []
    while i < j:
        (rssi, ) = struct.unpack_from('<b', buf, i)
        i += 1
        rssis.append(rssi)
    print(f'{st}, {b}, {rssis}')

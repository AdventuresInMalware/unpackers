import base64
import re
from sys import argv

def unpack(data):
    index = data.find('STARFALL')
    r = re.compile(r'STARFALL.{4}BD]=MMY',re.DOTALL)
    ismatch = r.findall(data)
    if not index:
        return None
    else:
        index += 12
        data2 = data[index:index+23212]
        payload = bytearray()
        for CurrentByte in data2:
            c = ord(CurrentByte) + 3
            c ^= 0x11
            payload.append(chr(c))
        payload = base64.b64decode(payload)
        return payload

if __name__ == '__main__':

    if len(argv) != 2:
        print "Please specify word document to process"
        exit()
    else:
        data = open(argv[1],'rb').read()
        payload = unpack(data)
        url_regex = re.compile('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        matches = url_regex.findall(payload)

        fname = argv[1] + '.payload.bin'

        print "Writing payload to :%s." % fname
        open(fname, 'wb').write(payload)

        print "\nCommand and Control URLs"
        for m in matches:
            if m != 'http://api.ipify.org':
                print m
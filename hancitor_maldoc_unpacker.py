import base64
import re
from sys import argv
import struct

def hancitor_decipher(data):

    #  Look for an 8 character upper case string followed by x08,x00
    r = re.compile(r'[A-Z]{8}\x08\x00',re.DOTALL)
    ismatch = r.findall(data)

    if not ismatch:
        return None
    else:
        # read the length of the embedded PE file.
        index = data.find(ismatch[0]) + 10
        length = struct.unpack('<h',data[index:index+2])[0]
        index += 2

        # calculate the value used to xor the data (expected first character of decoded data will be 84.
        xor_val = (ord(data[index]) + 3) ^ 84

        cipher_text = data[index:index+length]
        plain_text = bytearray()
        for CurrentByte in cipher_text:
            c = ord(CurrentByte) + 3
            c ^= xor_val
            plain_text.append(chr(c))
        plain_text = base64.b64decode(plain_text)
        return plain_text

if __name__ == '__main__':

    if len(argv) != 2:
        print "Please specify word document to process"
        exit()
    else:
        data = open(argv[1],'rb').read()
        payload = hancitor_decipher(data)
        url_regex = re.compile('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        matches = url_regex.findall(payload)

        fname = argv[1] + '.payload.bin'

        print "Writing payload to :%s." % fname
        open(fname, 'wb').write(payload)

        print "\nCommand and Control URLs"
        for m in matches:
            if m != 'http://api.ipify.org':
                print m

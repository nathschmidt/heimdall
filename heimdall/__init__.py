import hmac
import time
import array
import base64
import hashlib
import struct

def main():
    '''
        Main entry point for our script.
    '''

    secret_key = base64.b32decode(
        'G5LADDFSBWZP5UXURERJ5SBZBYITZU22EH74MAWOBXLGC5KLI2H4KMBQUAYV7HL2'
    )

    # secret_key = '12345678901234567890'

    # print secret_key
    print get_htop(secret_key, get_counter())

    exit(0)


def truncate(hsh, n=6):
    '''
    Truncate the hash into a six digit OTP. hash is
    assumed to be an array of bytes.
    '''
    # Grab our last byte, the value of the 
    # lower 4 bits used as the offset value
    # to determine the 
    offset = hsh[-1] & 0xf

    # Starting with our offset byte, take successive bytes.
    # 
    # We mask our 4 bytes (32-bits), agaist a 31-bit mask.
    # Resulting in an unsigned 31-bit integer.
    binvalue = \
        (hsh[offset] & 0x7f) << 24 \
        | (hsh[offset+1] & 0xff) << 16 \
        | (hsh[offset+2] & 0xff) << 8 \
        | (hsh[offset+3] & 0xff)

    # Take our binary value and mod it by 
    # 10^{digits}
    return binvalue % (10 ** n)


def get_counter(t=0):
    '''
        Get a counter value as per RFC 6238
    '''
    return (int(time.time()) - t) / 30


def get_htop(secret_key, counter):
    '''
        Retrieve a HOTP
    '''
    msg = struct.pack('>Q', counter)

    hm = hmac.new(
        secret_key,
        msg,
        hashlib.sha1
    )

    hsh = array.array('B', hm.digest())

    return truncate(hsh)


# def put_key(name, secret_key):
#     '''
#         Save a key to our secure store
#     '''
#     print "saving to our secure store"
#     return "<SAVED>"


# def get_key(name, secret_key):
#     '''
#         Save a key to our secure store
#     '''
#     print "getting from our secure store"
#     return "<SAVED>"

if __name__ == '__main__':
    main()
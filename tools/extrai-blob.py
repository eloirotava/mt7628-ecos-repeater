import sys,lzma,struct
d=open(sys.argv[1],'rb').read()
off=int(sys.argv[3],0) if len(sys.argv)>3 else 0
h=d[off:off+64]; size=struct.unpack('>I',h[12:16])[0]; name=h[32:64].rstrip(b'\0')
p=d[off+64:off+64+size]
z=p[0x2440:]
dec=lzma.LZMADecompressor(lzma.FORMAT_ALONE)
out=dec.decompress(z)
open(sys.argv[2],'wb').write(out)
print(sys.argv[1],name,'payload',size,'descomp',len(out))

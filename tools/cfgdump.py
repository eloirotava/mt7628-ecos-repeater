import re,struct,sys
h=open(sys.argv[1]).read()
mods={k:int(v) for k,v in re.findall(r'#define CFG_ID_([A-Z0-9]+)\s+(\d+)',h)}
names={}
for name,grp,idx,typ in re.findall(r'#define\s+(CFG_\w+)\s+CFG_([A-Z0-9]+)_\(\s*(\d+)\s*,\s*CFG_TYPE_(\w+)\)',h):
    if grp in mods: names[(mods[grp],int(idx))]=name
d=open(sys.argv[2],'rb').read(); o=int(sys.argv[3],0); end=o+0xf000
while o<end:
    i,l=struct.unpack('<II',d[o:o+8])
    if i in (0,0xffffffff) or l>0x1000: break
    mod,sub,typ,idx=i>>24,(i>>16)&255,(i>>8)&255,i&255
    v=d[o+8:o+8+l]
    if typ==1: s=str(struct.unpack('<i',v[:4])[0])
    elif typ==3: s='.'.join(map(str,v[:4]))
    elif typ==4: s=v[:6].hex(':')
    else: s=v.split(b'\0')[0].decode('latin1')
    print(f"{names.get((mod,sub),'?%d.%d'%(mod,sub))}{'['+str(idx)+']' if idx else ''} = {s}")
    o+=8+((l+3)&~3)

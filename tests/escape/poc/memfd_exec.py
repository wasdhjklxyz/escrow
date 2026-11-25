# INSIDE the jail: execute a real store ELF from an anonymous memfd.
# A memfd has no /nix/store path, so the record's store hashes don't cover
# the executed image. argv[1]=store ELF to copy, rest = argv for it.
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
src, rest = sys.argv[1], sys.argv[2:]
blob = open(src, "rb").read()
fd = libc.memfd_create(b"x", 0)
if fd < 0:
    print("BLOCKED memfd_create:", os.strerror(ctypes.get_errno())); sys.exit(0)
os.write(fd, blob)
AT_EMPTY_PATH = 0x1000
SYS_execveat = 322
args = [src] + rest
argv = (ctypes.c_char_p * (len(args)+1))(*[a.encode() for a in args], None)
envp = (ctypes.c_char_p * 1)(None)
libc.syscall(SYS_execveat, fd, b"", argv, envp, AT_EMPTY_PATH)
print("BLOCKED execveat(memfd):", os.strerror(ctypes.get_errno()))

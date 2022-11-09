#ifndef EVENT_H
#define EVENT_H

#include "arm64_syscall.h"

enum probe_handle{ //Corresponds to the probe function in bpf code
	SysEnter = 0,
	SysExit,
	SyscallEnter__Internal,
	SyscallExit__Internal,
	SchedProcessFork,
	SchedProcessExec,
	SchedProcessExit,
	SchedSwitch,
	DoExit,
	CapCapable,
	VfsWrite,
	VfsWriteRet,
	VfsWriteV,
	VfsWriteVRet,
	SecurityMmapAddr,
	SecurityMmapFile,
	SecurityFileMProtect,
	CommitCreds,
	SwitchTaskNS,
	KernelWrite,
	KernelWriteRet,
	CgroupAttachTask,
	CgroupMkdir,
	CgroupRmdir,
	SecurityBPRMCheck,
	SecurityFileOpen,
	SecurityInodeUnlink,
	SecurityInodeMknod,
	SecurityInodeSymlink,
	SecuritySocketCreate,
	SecuritySocketListen,
	SecuritySocketConnect,
	SecuritySocketAccept,
	SecuritySocketBind,
	SecuritySocketSetsockopt,
	SecuritySbMount,
	SecurityBPF,
	SecurityBPFMap,
	SecurityKernelReadFile,
	SecurityKernelPostReadFile,
	DoSplice,
	DoSpliceRet,
	ProcCreate,
	RegisterKprobe,
	RegisterKprobeRet,
	CallUsermodeHelper,
	DebugfsCreateFile,
	DebugfsCreateDir,
	DeviceAdd,
	RegisterChrdev,
	RegisterChrdevRet,
	DoInitModule,
	DoInitModuleRet,
	LoadElfPhdrs,
	Filldir64,
	SecurityFilePermission,
	TaskRename,
	UDPSendmsg,
	UDPDisconnect,
	UDPDestroySock,
	UDPv6DestroySock,
	InetSockSetState,
	TCPConnect,
	ICMPRecv,
	ICMPSend,
	ICMPv6Recv,
	ICMPv6Send,
	Pingv4Sendmsg,
	Pingv6Sendmsg,
	DefaultTcIngress,
	DefaultTcEgress,
	PrintSyscallTable,
	PrintNetSeqOps,
	SecurityInodeRename,
	DoSigaction,
};

enum Event_id_syscall{// Events that are defined(only for system call that has one fd)
	READ = 63,
	WRITE = 64,
	CLOSE = 57,
	FSTAT = 80,
	LSEEK = 62,
	MMAP = 222,
	MPROTECT = 226,
	RT_SIGRETURN = 139,
	IOCTL = 29,
	PREAD64 = 67,
	PWRITE64 = 68,
	READV = 65,
	WRITEV = 66,
	DUP = 23,
	SOCKET = 198,
	CONNECT = 203,
	ACCEPT = 202,
	SENDTO = 206,
	RECVFROM = 207,
	SENDMSG = 211,
	RECVMSG = 212,
	SHUTDOWN = 210,
	BIND = 200,
	LISTEN = 201,
	GETSOCKNAME = 204,
	GETPEERNAME = 205,
	SETSOCKOPT = 208,
	GETSOCKOPT = 209,
	EXECVE = 221,
	EXIT = 93,
	FCNTL = 25,
	FLOCK = 32,
	FSYNC = 82,
	FDATASYNC = 83,
	FTRUNCATE = 46,
	FCHDIR = 50,
	FCHMOD = 52,
	FCHOWN = 55,
	FSTATFS =44,
	READAHEAD = 213,
	FSETXATTR = 7,
	FGETXATTR = 10,
	FLISTXATTR = 13,
	FREMOVEXATTR = 16,
	GETDENTS64 = 61,
	FADVISE64 = 223,
	EXIT_GROUP = 94,
	EPOLL_CTL = 21,
	INOTIFY_ADD_WATCH = 27,
	INOTIFY_RM_WATCH = 28,
	OPENAT = 56,
	MKDIRAT = 34,
	MKNODAT = 33,
	FCHOWNAT = 54,
	UNLINKAT = 35,
	SYMLINKAT = 36,
	READLINKAT = 78,
	FCHMODAT = 53,
	FACCESSAT = 48,
	SYNC_FILE_RANGE = 84,
	VMSPLICE = 75,
	UTIMENSAT = 88,
	EPOLL_PWAIT = 22,
	FALLOCATE = 47,
	TIMERFD_SETTIME = 86,
	TIMERFD_GETTIME = 87,
	ACCEPT4 = 242,
	SIGNALFD4 = 74,
	DUP3 = 24,
	PREADV = 69,
	PWRITEV =70,
	PERF_EVENT_OPEN = 241,
	RECVMMSG = 243,
	NAME_TO_HANDLE_AT = 264,
	OPEN_BY_HANDLE_AT = 265,
	SYNCFS = 267,
	SENDMMSG = 269,
	SETNS = 268,
	FINIT_MODULE = 273,
	EXECVEAT = 281,
	PREADV2 = 286,
	PWRITEV2 = 287,
	STATX = 291,
	IO_URING_ENTER = 426,
	IO_URING_REGISTER = 427,
	OPEN_TREE = 428,
	FSCONFIG = 431,
	FSMOUNT = 432,
	FSPICK = 433,
	OPENAT2 = 437,
	FACCESSAT2 = 439,
	PROCESS_MADVISE = 440,
	EPOLL_PWAIT2 = 441,
	MOUNT_SETATTR = 442,
	QUOTACTL_FD = 443,
	LANDLOCK_ADD_RULE = 445,
	LANDLOCK_RESTRICT_SELF = 446,
	PROCESS_MRELEASE = 448,
};

enum Event_id_no_syscall{ // Events that are defined(not include system call)
	NET_PACKET = 700,
	DNS_REQUEST,
	DNS_RESPONSE,
	MAX_NET_ID,
	SYS_ENTER,
	SYS_EXIT,
	SCHED_PROCESS_FORK,
	SCHED_PROCESS_EXEC,
	SCHED_PROCESS_EXIT,
	SCHED_SWITCH,
	DO_EXIT,
	CAP_CAPABLE,
	VFS_WRITE,
	VFS_WRITEV,
	MEM_PROTALERT,
	COMMIT_CREDS,
	SWITCH_TASK_NS,
	MAGIC_WRITE,
	CGROUP_ATTACH_TASK,
	CGROUP_MKDIR,
	CGROUP_RMDIR,
	SECURITY_BPRM_CHECK,
	SECURITY_FILE_OPEN,
	SECURITY_INODE_UNLINK,
	SECURITY_SOCKET_CREATE,
	SECURITY_SOCKET_LISTEN,
	SECURITY_SOCKET_CONNECT,
	SECURITY_SOCKET_ACCEPT,
	SECURITY_SOCKET_BIND,
	SECURITY_SOCKET_SET_SOCKOPT,
	SECURITY_SBMOUNT,
	SECURITY_BPF,
	SECURITY_BPF_MAP,
	SECURITY_KERNEL_READ_FILE,
	SECURITY_INODE_MKNOD,
	SECURITY_POST_READFILE,
	SECURITY_INODE_SYMLINK_EVENT_ID,
	SECURITY_MMAP_FILE,
	SECURITY_FILE_MPROTECT,
	SOCKET_DUP,
	HIDDEN_INODES,
	KERNEL_WRITE,
	PROC_CREATE,
	KPROBE_ATTACH,
	CALLUSER_MODE_HELPER,
	DIR_TYPIPE_SPLICE,
	DEBUG_FS_CREATE_FILE,
	PRINT_SYSCALL_TABLE,
	DEBUG_FS_CREATE_DIR,
	DEVIC_EADD,
	REGISTER_CHRDEV,
	SHARED_OBJECT_LOADED,
	DOINIT_MODULE,
	SOCKET_ACCEPT,
	LOADEL_FPHDRS,
	HOOKED_PROC_FOPS,
	PRINT_NET_SEQ_OPS,
	TASK_RENAME,
	SECURITY_INODE_RENAME,
	DOSIG_ACTION,
	MAX_COMMON_ID,
};

struct probeDependency{
	enum probe_handle Handle;
	char Required; // should tracee fail if probe fails to attach
};

struct ArgMeta{
	char* Type;
	char *Name;
};

#define MAX_EVENT_NUM 1024
#define MAX_PROBE_NUM 15
#define MAX_SET_NUM 10
#define MAX_ARG_NUM 20

struct Event{
	int ID32Bit;
    int ID64Bit;  
	char* Name ;     
	char* DocPath;     
	char Internal;   
	char Syscall;
	int Probenum;     
	struct probeDependency Probes[MAX_PROBE_NUM];
	int Setnum;
	char *Sets[MAX_SET_NUM];   // The sum of sets that belong to
	int Argnum;
	struct ArgMeta Params[MAX_ARG_NUM];     
};

struct Event eventDefinitions[MAX_EVENT_NUM] = {
    {sys32read, READ, "read", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 3, {{"int", "fd"}, {"void*", "buf"}, {"size_t", "count"}}}, 
    {sys32write, WRITE, "write", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 3, {{"int", "fd"}, {"void*", "buf"}, {"size_t", "count"}}}, 
    {sys32close, CLOSE, "close", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_ops"}, 1, {{"int", "fd"}}}, 
    {sys32fstat, FSTAT, "fstat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_attr"}, 2, {{"int", "fd"}, {"structstat*", "statbuf"}}}, 
    {sys32lseek, LSEEK, "lseek", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 3, {{"int", "fd"}, {"off_t", "offset"}, {"unsignedint", "whence"}}}, 
    {sys32mmap, MMAP, "mmap", NULL, '\0', 1, 0, {}, 3, {"syscalls", "proc", "proc_mem"}, 6, {{"void*", "addr"}, {"size_t", "length"}, {"int", "prot"}, {"int", "flags"}, {"int", "fd"}, {"off_t", "off"}}}, 
    {sys32mprotect, MPROTECT, "mprotect", NULL, '\0', 1, 0, {}, 3, {"syscalls", "proc", "proc_mem"}, 3, {{"void*", "addr"}, {"size_t", "len"}, {"int", "prot"}}}, 
    {sys32rt_sigreturn, RT_SIGRETURN, "rt_sigreturn", NULL, '\0', 1, 0, {}, 2, {"syscalls", "signals"}, 0, {}}, 
    {sys32ioctl, IOCTL, "ioctl", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_fd_ops"}, 3, {{"int", "fd"}, {"unsignedlong", "request"}, {"unsignedlong", "arg"}}}, 
    {sys32pread64, PREAD64, "pread64", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 4, {{"int", "fd"}, {"void*", "buf"}, {"size_t", "count"}, {"off_t", "offset"}}}, 
    {sys32pwrite64, PWRITE64, "pwrite64", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 4, {{"int", "fd"}, {"constvoid*", "buf"}, {"size_t", "count"}, {"off_t", "offset"}}}, 
    {sys32readv, READV, "readv", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 3, {{"int", "fd"}, {"conststructiovec*", "iov"}, {"int", "iovcnt"}}}, 
    {sys32writev, WRITEV, "writev", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 3, {{"int", "fd"}, {"conststructiovec*", "iov"}, {"int", "iovcnt"}}}, 
    {sys32dup, DUP, "dup", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_fd_ops"}, 1, {{"int", "oldfd"}}}, 
    {sys32socket, SOCKET, "socket", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "net", "net_sock"}, 3, {{"int", "domain"}, {"int", "type"}, {"int", "protocol"}}}, 
    {sys32connect, CONNECT, "connect", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "net", "net_sock"}, 3, {{"int", "sockfd"}, {"structsockaddr*", "addr"}, {"int", "addrlen"}}}, 
    {sys32undefined, ACCEPT, "accept", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "net", "net_sock"}, 3, {{"int", "sockfd"}, {"structsockaddr*", "addr"}, {"int*", "addrlen"}}}, 
    {sys32sendto, SENDTO, "sendto", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_snd_rcv"}, 6, {{"int", "sockfd"}, {"void*", "buf"}, {"size_t", "len"}, {"int", "flags"}, {"structsockaddr*", "dest_addr"}, {"int", "addrlen"}}}, 
    {sys32recvfrom, RECVFROM, "recvfrom", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_snd_rcv"}, 6, {{"int", "sockfd"}, {"void*", "buf"}, {"size_t", "len"}, {"int", "flags"}, {"structsockaddr*", "src_addr"}, {"int*", "addrlen"}}}, 
    {sys32sendmsg, SENDMSG, "sendmsg", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_snd_rcv"}, 3, {{"int", "sockfd"}, {"structmsghdr*", "msg"}, {"int", "flags"}}}, 
    {sys32recvmsg, RECVMSG, "recvmsg", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_snd_rcv"}, 3, {{"int", "sockfd"}, {"structmsghdr*", "msg"}, {"int", "flags"}}}, 
    {sys32shutdown, SHUTDOWN, "shutdown", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_sock"}, 2, {{"int", "sockfd"}, {"int", "how"}}}, 
    {sys32bind, BIND, "bind", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "net", "net_sock"}, 3, {{"int", "sockfd"}, {"structsockaddr*", "addr"}, {"int", "addrlen"}}}, 
    {sys32listen, LISTEN, "listen", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "net", "net_sock"}, 2, {{"int", "sockfd"}, {"int", "backlog"}}}, 
    {sys32getsockname, GETSOCKNAME, "getsockname", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "net", "net_sock"}, 3, {{"int", "sockfd"}, {"structsockaddr*", "addr"}, {"int*", "addrlen"}}}, 
    {sys32getpeername, GETPEERNAME, "getpeername", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_sock"}, 3, {{"int", "sockfd"}, {"structsockaddr*", "addr"}, {"int*", "addrlen"}}}, 
    {sys32setsockopt, SETSOCKOPT, "setsockopt", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_sock"}, 5, {{"int", "sockfd"}, {"int", "level"}, {"int", "optname"}, {"constvoid*", "optval"}, {"int", "optlen"}}}, 
    {sys32getsockopt, GETSOCKOPT, "getsockopt", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_sock"}, 5, {{"int", "sockfd"}, {"int", "level"}, {"int", "optname"}, {"void*", "optval"}, {"int*", "optlen"}}}, 
    {sys32execve, EXECVE, "execve", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "proc", "proc_life"}, 3, {{"constchar*", "pathname"}, {"constchar*const*", "argv"}, {"constchar*const*", "envp"}}}, 
    {sys32exit, EXIT, "exit", NULL, '\0', 1, 0, {}, 3, {"syscalls", "proc", "proc_life"}, 1, {{"int", "status"}}}, 
    {sys32fcntl, FCNTL, "fcntl", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_fd_ops"}, 3, {{"int", "fd"}, {"int", "cmd"}, {"unsignedlong", "arg"}}}, 
    {sys32flock, FLOCK, "flock", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_fd_ops"}, 2, {{"int", "fd"}, {"int", "operation"}}}, 
    {sys32fsync, FSYNC, "fsync", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_sync"}, 1, {{"int", "fd"}}}, 
    {sys32fdatasync, FDATASYNC, "fdatasync", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_sync"}, 1, {{"int", "fd"}}}, 
    {sys32ftruncate, FTRUNCATE, "ftruncate", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_ops"}, 2, {{"int", "fd"}, {"off_t", "length"}}}, 
    {sys32fchdir, FCHDIR, "fchdir", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_dir_ops"}, 1, {{"int", "fd"}}}, 
    {sys32fchmod, FCHMOD, "fchmod", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_attr"}, 2, {{"int", "fd"}, {"mode_t", "mode"}}}, 
    {sys32fchown32, FCHOWN, "fchown", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_attr"}, 3, {{"int", "fd"}, {"uid_t", "owner"}, {"gid_t", "group"}}}, 
    {sys32fstatfs, FSTATFS, "fstatfs", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_info"}, 2, {{"int", "fd"}, {"structstatfs*", "buf"}}}, 
    {sys32readahead, READAHEAD, "readahead", NULL, '\0', 1, 0, {}, 2, {"syscalls", "fs"}, 3, {{"int", "fd"}, {"off_t", "offset"}, {"size_t", "count"}}}, 
    {sys32fsetxattr, FSETXATTR, "fsetxattr", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_attr"}, 5, {{"int", "fd"}, {"constchar*", "name"}, {"constvoid*", "value"}, {"size_t", "size"}, {"int", "flags"}}}, 
    {sys32fgetxattr, FGETXATTR, "fgetxattr", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_attr"}, 4, {{"int", "fd"}, {"constchar*", "name"}, {"void*", "value"}, {"size_t", "size"}}}, 
    {sys32flistxattr, FLISTXATTR, "flistxattr", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_attr"}, 3, {{"int", "fd"}, {"char*", "list"}, {"size_t", "size"}}}, 
    {sys32fremovexattr, FREMOVEXATTR, "fremovexattr", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_attr"}, 2, {{"int", "fd"}, {"constchar*", "name"}}}, 
    {sys32getdents64, GETDENTS64, "getdents64", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_dir_ops"}, 3, {{"unsignedint", "fd"}, {"structlinux_dirent64*", "dirp"}, {"unsignedint", "count"}}}, 
    {sys32fadvise64, FADVISE64, "fadvise64", NULL, '\0', 1, 0, {}, 2, {"syscalls", "fs"}, 4, {{"int", "fd"}, {"off_t", "offset"}, {"size_t", "len"}, {"int", "advice"}}}, 
    {sys32exit_group, EXIT_GROUP, "exit_group", NULL, '\0', 1, 0, {}, 3, {"syscalls", "proc", "proc_life"}, 1, {{"int", "status"}}}, 
    {sys32epoll_ctl, EPOLL_CTL, "epoll_ctl", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_mux_io"}, 4, {{"int", "epfd"}, {"int", "op"}, {"int", "fd"}, {"structepoll_event*", "event"}}}, 
    {sys32inotify_add_watch, INOTIFY_ADD_WATCH, "inotify_add_watch", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_monitor"}, 3, {{"int", "fd"}, {"constchar*", "pathname"}, {"u32", "mask"}}}, 
    {sys32inotify_rm_watch, INOTIFY_RM_WATCH, "inotify_rm_watch", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_monitor"}, 2, {{"int", "fd"}, {"int", "wd"}}}, 
    {sys32openat, OPENAT, "openat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_ops"}, 4, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"int", "flags"}, {"mode_t", "mode"}}}, 
    {sys32mkdirat, MKDIRAT, "mkdirat", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_dir_ops"}, 3, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"mode_t", "mode"}}}, 
    {sys32mknodat, MKNODAT, "mknodat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_ops"}, 4, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"mode_t", "mode"}, {"dev_t", "dev"}}}, 
    {sys32fchownat, FCHOWNAT, "fchownat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_attr"}, 5, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"uid_t", "owner"}, {"gid_t", "group"}, {"int", "flags"}}}, 
    {sys32unlinkat, UNLINKAT, "unlinkat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_link_ops"}, 3, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"int", "flags"}}}, 
    {sys32symlinkat, SYMLINKAT, "symlinkat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_link_ops"}, 3, {{"constchar*", "target"}, {"int", "newdirfd"}, {"constchar*", "linkpath"}}}, 
    {sys32readlinkat, READLINKAT, "readlinkat", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_link_ops"}, 4, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"char*", "buf"}, {"int", "bufsiz"}}}, 
    {sys32fchmodat, FCHMODAT, "fchmodat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_attr"}, 4, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"mode_t", "mode"}, {"int", "flags"}}}, 
    {sys32faccessat, FACCESSAT, "faccessat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_attr"}, 4, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"int", "mode"}, {"int", "flags"}}}, 
    {sys32sync_file_range, SYNC_FILE_RANGE, "sync_file_range", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_sync"}, 4, {{"int", "fd"}, {"off_t", "offset"}, {"off_t", "nbytes"}, {"unsignedint", "flags"}}}, 
    {sys32vmsplice, VMSPLICE, "vmsplice", NULL, '\0', 1, 0, {}, 3, {"syscalls", "ipc", "ipc_pipe"}, 4, {{"int", "fd"}, {"conststructiovec*", "iov"}, {"unsignedlong", "nr_segs"}, {"unsignedint", "flags"}}}, 
    {sys32utimensat_time64, UTIMENSAT, "utimensat", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_attr"}, 4, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"structtimespec*", "times"}, {"int", "flags"}}}, 
    {sys32epoll_pwait, EPOLL_PWAIT, "epoll_pwait", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_mux_io"}, 6, {{"int", "epfd"}, {"structepoll_event*", "events"}, {"int", "maxevents"}, {"int", "timeout"}, {"constsigset_t*", "sigmask"}, {"size_t", "sigsetsize"}}}, 
    {sys32fallocate, FALLOCATE, "fallocate", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_ops"}, 4, {{"int", "fd"}, {"int", "mode"}, {"off_t", "offset"}, {"off_t", "len"}}}, 
    {sys32timerfd_settime64, TIMERFD_SETTIME, "timerfd_settime", NULL, '\0', 1, 0, {}, 3, {"syscalls", "time", "time_timer"}, 4, {{"int", "fd"}, {"int", "flags"}, {"conststructitimerspec*", "new_value"}, {"structitimerspec*", "old_value"}}}, 
    {sys32timerfd_gettime64, TIMERFD_GETTIME, "timerfd_gettime", NULL, '\0', 1, 0, {}, 3, {"syscalls", "time", "time_timer"}, 2, {{"int", "fd"}, {"structitimerspec*", "curr_value"}}}, 
    {sys32accept4, ACCEPT4, "accept4", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "net", "net_sock"}, 4, {{"int", "sockfd"}, {"structsockaddr*", "addr"}, {"int*", "addrlen"}, {"int", "flags"}}}, 
    {sys32signalfd4, SIGNALFD4, "signalfd4", NULL, '\0', 1, 0, {}, 2, {"syscalls", "signals"}, 4, {{"int", "fd"}, {"constsigset_t*", "mask"}, {"size_t", "sizemask"}, {"int", "flags"}}}, 
    {sys32dup3, DUP3, "dup3", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_fd_ops"}, 3, {{"int", "oldfd"}, {"int", "newfd"}, {"int", "flags"}}}, 
    {sys32preadv, PREADV, "preadv", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 5, {{"int", "fd"}, {"conststructiovec*", "iov"}, {"unsignedlong", "iovcnt"}, {"unsignedlong", "pos_l"}, {"unsignedlong", "pos_h"}}}, 
    {sys32pwritev, PWRITEV, "pwritev", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 5, {{"int", "fd"}, {"conststructiovec*", "iov"}, {"unsignedlong", "iovcnt"}, {"unsignedlong", "pos_l"}, {"unsignedlong", "pos_h"}}}, 
    {sys32perf_event_open, PERF_EVENT_OPEN, "perf_event_open", NULL, '\0', 1, 0, {}, 2, {"syscalls", "system"}, 5, {{"structperf_event_attr*", "attr"}, {"pid_t", "pid"}, {"int", "cpu"}, {"int", "group_fd"}, {"unsignedlong", "flags"}}}, 
    {sys32recvmmsg_time64, RECVMMSG, "recvmmsg", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_snd_rcv"}, 5, {{"int", "sockfd"}, {"structmmsghdr*", "msgvec"}, {"unsignedint", "vlen"}, {"int", "flags"}, {"structtimespec*", "timeout"}}}, 
    {sys32name_to_handle_at, NAME_TO_HANDLE_AT, "name_to_handle_at", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_ops"}, 5, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"structfile_handle*", "handle"}, {"int*", "mount_id"}, {"int", "flags"}}}, 
    {sys32open_by_handle_at, OPEN_BY_HANDLE_AT, "open_by_handle_at", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_ops"}, 3, {{"int", "mount_fd"}, {"structfile_handle*", "handle"}, {"int", "flags"}}}, 
    {sys32syncfs, SYNCFS, "syncfs", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_sync"}, 1, {{"int", "fd"}}}, 
    {sys32sendmmsg, SENDMMSG, "sendmmsg", NULL, '\0', 1, 0, {}, 3, {"syscalls", "net", "net_snd_rcv"}, 4, {{"int", "sockfd"}, {"structmmsghdr*", "msgvec"}, {"unsignedint", "vlen"}, {"int", "flags"}}}, 
    {sys32setns, SETNS, "setns", NULL, '\0', 1, 0, {}, 2, {"syscalls", "proc"}, 2, {{"int", "fd"}, {"int", "nstype"}}}, 
    {sys32finit_module, FINIT_MODULE, "finit_module", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "system", "system_module"}, 3, {{"int", "fd"}, {"constchar*", "param_values"}, {"int", "flags"}}}, 
    {sys32execveat, EXECVEAT, "execveat", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "proc", "proc_life"}, 5, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"constchar*const*", "argv"}, {"constchar*const*", "envp"}, {"int", "flags"}}}, 
    {sys32preadv2, PREADV2, "preadv2", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 6, {{"int", "fd"}, {"conststructiovec*", "iov"}, {"unsignedlong", "iovcnt"}, {"unsignedlong", "pos_l"}, {"unsignedlong", "pos_h"}, {"int", "flags"}}}, 
    {sys32pwritev2, PWRITEV2, "pwritev2", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_read_write"}, 6, {{"int", "fd"}, {"conststructiovec*", "iov"}, {"unsignedlong", "iovcnt"}, {"unsignedlong", "pos_l"}, {"unsignedlong", "pos_h"}, {"int", "flags"}}}, 
    {sys32statx, STATX, "statx", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_file_attr"}, 5, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"int", "flags"}, {"unsignedint", "mask"}, {"structstatx*", "statxbuf"}}}, 
    {sys32io_uring_enter, IO_URING_ENTER, "io_uring_enter", NULL, '\0', 1, 0, {}, 1, {"syscalls"}, 5, {{"unsignedint", "fd"}, {"unsignedint", "to_submit"}, {"unsignedint", "min_complete"}, {"unsignedint", "flags"}, {"sigset_t*", "sig"}}}, 
    {sys32io_uring_register, IO_URING_REGISTER, "io_uring_register", NULL, '\0', 1, 0, {}, 1, {"syscalls"}, 4, {{"unsignedint", "fd"}, {"unsignedint", "opcode"}, {"void*", "arg"}, {"unsignedint", "nr_args"}}}, 
    {sys32open_tree, OPEN_TREE, "open_tree", NULL, '\0', 1, 0, {}, 1, {"syscalls"}, 3, {{"int", "dfd"}, {"constchar*", "filename"}, {"unsignedint", "flags"}}}, 
    {sys32fsconfig, FSCONFIG, "fsconfig", NULL, '\0', 1, 0, {}, 2, {"syscalls", "fs"}, 5, {{"int*", "fs_fd"}, {"unsignedint", "cmd"}, {"constchar*", "key"}, {"constvoid*", "value"}, {"int", "aux"}}}, 
    {sys32fsmount, FSMOUNT, "fsmount", NULL, '\0', 1, 0, {}, 2, {"syscalls", "fs"}, 3, {{"int", "fsfd"}, {"unsignedint", "flags"}, {"unsignedint", "ms_flags"}}}, 
    {sys32fspick, FSPICK, "fspick", NULL, '\0', 1, 0, {}, 2, {"syscalls", "fs"}, 3, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"unsignedint", "flags"}}}, 
    {sys32openat2, OPENAT2, "openat2", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_ops"}, 4, {{"int", "dirfd"}, {"constchar*", "pathname"}, {"structopen_how*", "how"}, {"size_t", "size"}}}, 
    {sys32faccessat2, FACCESSAT2, "faccessat2", NULL, '\0', 1, 0, {}, 4, {"default", "syscalls", "fs", "fs_file_attr"}, 4, {{"int", "fd"}, {"constchar*", "path"}, {"int", "mode"}, {"int", "flag"}}}, 
    {sys32process_madvise, PROCESS_MADVISE, "process_madvise", NULL, '\0', 1, 0, {}, 1, {"syscalls"}, 5, {{"int", "pidfd"}, {"void*", "addr"}, {"size_t", "length"}, {"int", "advice"}, {"unsignedlong", "flags"}}}, 
    {sys32epoll_pwait2, EPOLL_PWAIT2, "epoll_pwait2", NULL, '\0', 1, 0, {}, 3, {"syscalls", "fs", "fs_mux_io"}, 5, {{"int", "fd"}, {"structepoll_event*", "events"}, {"int", "maxevents"}, {"conststructtimespec*", "timeout"}, {"constsigset_t*", "sigset"}}}, 
    {sys32mount_setattr, MOUNT_SETATTR, "mount_setattr", NULL, '\0', 1, 0, {}, 2, {"syscalls", "fs"}, 5, {{"int", "dfd"}, {"char*", "path"}, {"unsignedint", "flags"}, {"structmount_attr*", "uattr"}, {"size_t", "usize"}}}, 
    {sys32quotactl_fd, QUOTACTL_FD, "quotactl_fd", NULL, '\0', 1, 0, {}, 2, {"syscalls", "fs"}, 4, {{"unsignedint", "fd"}, {"unsignedint", "cmd"}, {"qid_t", "id"}, {"void*", "addr"}}}, 
    {sys32landlock_add_rule, LANDLOCK_ADD_RULE, "landlock_add_rule", NULL, '\0', 1, 0, {}, 3, {"syscalls", "proc", "fs"}, 4, {{"int", "ruleset_fd"}, {"landlock_rule_type", "rule_type"}, {"void*", "rule_attr"}, {"u32", "flags"}}}, 
    {sys32landlock_restrict_self, LANDLOCK_RESTRICT_SELF, "landlock_restrict_self", NULL, '\0', 1, 0, {}, 3, {"syscalls", "proc", "fs"}, 2, {{"int", "ruleset_fd"}, {"u32", "flags"}}}, 
    {sys32process_mrelease, PROCESS_MRELEASE, "process_mrelease", NULL, '\0', 1, 0, {}, 1, {"syscalls"}, 2, {{"int", "pidfd"}, {"unsignedint", "flags"}}}, 
    {sys32undefined, SYS_ENTER, "sys_enter", NULL, '\0', 0, 1, {{SysEnter, true}}, 0, {}, 1, {{"int", "syscall"}}}, 
    {sys32undefined, SYS_EXIT, "sys_exit", NULL, '\0', 0, 1, {{SysExit, true}}, 0, {}, 1, {{"int", "syscall"}}}, 
    {sys32undefined, SCHED_PROCESS_FORK, "sched_process_fork", NULL, '\0', 0, 1, {{SchedProcessFork, true}}, 0, {}, 9, {{"int", "parent_tid"}, {"int", "parent_ns_tid"}, {"int", "parent_pid"}, {"int", "parent_ns_pid"}, {"int", "child_tid"}, {"int", "child_ns_tid"}, {"int", "child_pid"}, {"int", "child_ns_pid"}, {"unsignedlong", "start_time"}}}, 
    {sys32undefined, SCHED_PROCESS_EXEC, "sched_process_exec", NULL, '\0', 0, 2, {{SchedProcessExec, true}, {LoadElfPhdrs, false}}, 2, {"default", "proc"}, 15, {{"constchar*", "cmdpath"}, {"constchar*", "pathname"}, {"constchar**", "argv"}, {"constchar**", "env"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}, {"int", "invoked_from_kernel"}, {"unsignedlong", "ctime"}, {"umode_t", "stdin_type"}, {"umode_t", "inode_mode"}, {"constchar*", "interp"}, {"constchar*", "interpreter_pathname"}, {"dev_t", "interpreter_dev"}, {"unsignedlong", "interpreter_inode"}, {"unsignedlong", "interpreter_ctime"}}}, 
    {sys32undefined, SCHED_PROCESS_EXIT, "sched_process_exit", NULL, '\0', 0, 1, {{SchedProcessExit, true}}, 3, {"default", "proc", "proc_life"}, 1, {{"long", "exit_code"}}}, 
    {sys32undefined, SCHED_SWITCH, "sched_switch", NULL, '\0', 0, 1, {{SchedSwitch, true}}, 0, {}, 5, {{"int", "cpu"}, {"int", "prev_tid"}, {"constchar*", "prev_comm"}, {"int", "next_tid"}, {"constchar*", "next_comm"}}}, 
    {sys32undefined, DO_EXIT, "do_exit", NULL, '\0', 0, 1, {{DoExit, true}}, 2, {"proc", "proc_life"}, 0, {}}, 
    {sys32undefined, CAP_CAPABLE, "cap_capable", NULL, '\0', 0, 1, {{CapCapable, true}}, 1, {"default"}, 2, {{"int", "cap"}, {"int", "syscall"}}}, 
    {sys32undefined, VFS_WRITE, "vfs_write", NULL, '\0', 0, 2, {{VfsWrite, true}, {VfsWriteRet, true}}, 0, {}, 5, {{"constchar*", "pathname"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}, {"size_t", "count"}, {"off_t", "pos"}}}, 
    {sys32undefined, VFS_WRITEV, "vfs_writev", NULL, '\0', 0, 2, {{VfsWriteV, true}, {VfsWriteVRet, true}}, 0, {}, 5, {{"constchar*", "pathname"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}, {"unsignedlong", "vlen"}, {"off_t", "pos"}}}, 
    {sys32undefined, MEM_PROTALERT, "mem_prot_alert", NULL, '\0', 0, 3, {{SecurityMmapAddr, true}, {SecurityFileMProtect, true}, {SyscallEnter__Internal, true}}, 0, {}, 1, {{"u32", "alert"}}}, 
    {sys32undefined, COMMIT_CREDS, "commit_creds", NULL, '\0', 0, 1, {{CommitCreds, true}}, 0, {}, 3, {{"slim_cred_t", "old_cred"}, {"slim_cred_t", "new_cred"}, {"int", "syscall"}}}, 
    {sys32undefined, SWITCH_TASK_NS, "switch_task_ns", NULL, '\0', 0, 1, {{SwitchTaskNS, true}}, 0, {}, 7, {{"pid_t", "pid"}, {"u32", "new_mnt"}, {"u32", "new_pid"}, {"u32", "new_uts"}, {"u32", "new_ipc"}, {"u32", "new_net"}, {"u32", "new_cgroup"}}}, 
    {sys32undefined, MAGIC_WRITE, "magic_write", "security_alerts/magic_write.md", '\0', 0, 6, {{VfsWrite, true}, {VfsWriteRet, true}, {VfsWriteV, true}, {VfsWriteVRet, true}, {KernelWrite, true}, {KernelWriteRet, true}}, 0, {}, 4, {{"constchar*", "pathname"}, {"bytes", "bytes"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}}}, 
    {sys32undefined, CGROUP_ATTACH_TASK, "cgroup_attach_task", NULL, '\0', 0, 1, {{CgroupAttachTask, true}}, 0, {}, 3, {{"constchar*", "cgroup_path"}, {"constchar*", "comm"}, {"pid_t", "pid"}}}, 
    {sys32undefined, CGROUP_MKDIR, "cgroup_mkdir", NULL, '\0', 0, 1, {{CgroupMkdir, true}}, 0, {}, 3, {{"u64", "cgroup_id"}, {"constchar*", "cgroup_path"}, {"u32", "hierarchy_id"}}}, 
    {sys32undefined, CGROUP_RMDIR, "cgroup_rmdir", NULL, '\0', 0, 1, {{CgroupRmdir, true}}, 0, {}, 3, {{"u64", "cgroup_id"}, {"constchar*", "cgroup_path"}, {"u32", "hierarchy_id"}}}, 
    {sys32undefined, SECURITY_BPRM_CHECK, "security_bprm_check", NULL, '\0', 0, 1, {{SecurityBPRMCheck, true}}, 4, {"default", "lsm_hooks", "proc", "proc_life"}, 3, {{"constchar*", "pathname"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}}}, 
    {sys32undefined, SECURITY_FILE_OPEN, "security_file_open", NULL, '\0', 0, 2, {{SecurityFileOpen, true}, {SyscallEnter__Internal, true}}, 4, {"default", "lsm_hooks", "fs", "fs_file_ops"}, 7, {{"constchar*", "pathname"}, {"int", "flags"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}, {"unsignedlong", "ctime"}, {"constchar*", "syscall_pathname"}, {"int", "syscall"}}}, 
    {sys32undefined, SECURITY_INODE_UNLINK, "security_inode_unlink", NULL, '\0', 0, 1, {{SecurityInodeUnlink, true}}, 4, {"default", "lsm_hooks", "fs", "fs_file_ops"}, 4, {{"constchar*", "pathname"}, {"unsignedlong", "inode"}, {"dev_t", "dev"}, {"u64", "ctime"}}}, 
    {sys32undefined, SECURITY_SOCKET_CREATE, "security_socket_create", NULL, '\0', 0, 1, {{SecuritySocketCreate, false}}, 4, {"default", "lsm_hooks", "net", "net_sock"}, 4, {{"int", "family"}, {"int", "type"}, {"int", "protocol"}, {"int", "kern"}}}, 
    {sys32undefined, SECURITY_SOCKET_LISTEN, "security_socket_listen", NULL, '\0', 0, 2, {{SecuritySocketListen, true}, {SyscallEnter__Internal, true}}, 4, {"default", "lsm_hooks", "net", "net_sock"}, 3, {{"int", "sockfd"}, {"structsockaddr*", "local_addr"}, {"int", "backlog"}}}, 
    {sys32undefined, SECURITY_SOCKET_CONNECT, "security_socket_connect", NULL, '\0', 0, 2, {{SecuritySocketConnect, true}, {SyscallEnter__Internal, true}}, 4, {"default", "lsm_hooks", "net", "net_sock"}, 2, {{"int", "sockfd"}, {"structsockaddr*", "remote_addr"}}}, 
    {sys32undefined, SECURITY_SOCKET_ACCEPT, "security_socket_accept", NULL, '\0', 0, 2, {{SecuritySocketAccept, true}, {SyscallEnter__Internal, true}}, 4, {"default", "lsm_hooks", "net", "net_sock"}, 2, {{"int", "sockfd"}, {"structsockaddr*", "local_addr"}}}, 
    {sys32undefined, SECURITY_SOCKET_BIND, "security_socket_bind", NULL, '\0', 0, 2, {{SecuritySocketBind, true}, {SyscallEnter__Internal, true}}, 4, {"default", "lsm_hooks", "net", "net_sock"}, 2, {{"int", "sockfd"}, {"structsockaddr*", "local_addr"}}}, 
    {sys32undefined, SECURITY_SOCKET_SET_SOCKOPT, "security_socket_setsockopt", "lsm_hooks/security_socket_setsockopt.md", '\0', 0, 2, {{SecuritySocketSetsockopt, true}, {SyscallEnter__Internal, true}}, 4, {"default", "lsm_hooks", "net", "net_sock"}, 4, {{"int", "sockfd"}, {"int", "level"}, {"int", "optname"}, {"structsockaddr*", "local_addr"}}}, 
    {sys32undefined, SECURITY_SBMOUNT, "security_sb_mount", NULL, '\0', 0, 1, {{SecuritySbMount, true}}, 3, {"default", "lsm_hooks", "fs"}, 4, {{"constchar*", "dev_name"}, {"constchar*", "path"}, {"constchar*", "type"}, {"unsignedlong", "flags"}}}, 
    {sys32undefined, SECURITY_BPF, "security_bpf", NULL, '\0', 0, 1, {{SecurityBPF, true}}, 1, {"lsm_hooks"}, 1, {{"int", "cmd"}}}, 
    {sys32undefined, SECURITY_BPF_MAP, "security_bpf_map", NULL, '\0', 0, 1, {{SecurityBPFMap, true}}, 1, {"lsm_hooks"}, 2, {{"unsignedint", "map_id"}, {"constchar*", "map_name"}}}, 
    {sys32undefined, SECURITY_KERNEL_READ_FILE, "security_kernel_read_file", NULL, '\0', 0, 1, {{SecurityKernelReadFile, true}}, 1, {"lsm_hooks"}, 5, {{"constchar*", "pathname"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}, {"int", "type"}, {"unsignedlong", "ctime"}}}, 
    {sys32undefined, SECURITY_POST_READFILE, "security_kernel_post_read_file", NULL, '\0', 0, 1, {{SecurityKernelPostReadFile, true}}, 1, {"lsm_hooks"}, 3, {{"constchar*", "pathname"}, {"long", "size"}, {"int", "type"}}}, 
    {sys32undefined, SECURITY_INODE_MKNOD, "security_inode_mknod", NULL, '\0', 0, 1, {{SecurityInodeMknod, true}}, 1, {"lsm_hooks"}, 3, {{"constchar*", "file_name"}, {"umode_t", "mode"}, {"dev_t", "dev"}}}, 
    {sys32undefined, SECURITY_INODE_SYMLINK_EVENT_ID, "security_inode_symlink", NULL, '\0', 0, 1, {{SecurityInodeSymlink, true}}, 3, {"lsm_hooks", "fs", "fs_file_ops"}, 2, {{"constchar*", "linkpath"}, {"constchar*", "target"}}}, 
    {sys32undefined, SECURITY_MMAP_FILE, "security_mmap_file", NULL, '\0', 0, 1, {{SecurityMmapFile, true}}, 5, {"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"}, 8, {{"constchar*", "pathname"}, {"int", "flags"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}, {"unsignedlong", "ctime"}, {"int", "prot"}, {"int", "mmap_flags"}, {"int", "syscall"}}}, 
    {sys32undefined, SECURITY_FILE_MPROTECT, "security_file_mprotect", NULL, '\0', 0, 2, {{SecurityFileMProtect, true}, {SyscallEnter__Internal, true}}, 5, {"lsm_hooks", "proc", "proc_mem", "fs", "fs_file_ops"}, 3, {{"constchar*", "pathname"}, {"int", "prot"}, {"unsignedlong", "ctime"}}}, 
    {sys32undefined, SOCKET_DUP, "socket_dup", NULL, '\0', 0, 0, {}, 0, {}, 3, {{"int", "oldfd"}, {"int", "newfd"}, {"structsockaddr*", "remote_addr"}}}, 
    {sys32undefined, HIDDEN_INODES, "hidden_inodes", NULL, '\0', 0, 1, {{Filldir64, true}}, 0, {}, 1, {{"char*", "hidden_process"}}}, 
    {sys32undefined, KERNEL_WRITE, "__kernel_write", NULL, '\0', 0, 2, {{KernelWrite, true}, {KernelWriteRet, true}}, 0, {}, 5, {{"constchar*", "pathname"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}, {"size_t", "count"}, {"off_t", "pos"}}}, 
    {sys32undefined, DIR_TYPIPE_SPLICE, "dirty_pipe_splice", NULL, '\0', 0, 2, {{DoSplice, true}, {DoSpliceRet, true}}, 0, {}, 7, {{"unsignedlong", "inode_in"}, {"umode_t", "in_file_type"}, {"constchar*", "in_file_path"}, {"loff_t", "exposed_data_start_offset"}, {"size_t", "exposed_data_len"}, {"unsignedlong", "inode_out"}, {"unsignedint", "out_pipe_last_buffer_flags"}}},
    {sys32undefined, NET_PACKET, "net_packet", NULL, '\0', 0, 13, {{UDPSendmsg, true}, {UDPDisconnect, true}, {UDPDestroySock, true}, {UDPv6DestroySock, true}, {InetSockSetState, true}, {TCPConnect, true}, {ICMPRecv, true}, {ICMPSend, true}, {ICMPv6Recv, true}, {ICMPv6Send, true}, {Pingv4Sendmsg, true}, {Pingv6Sendmsg, true}, {SecuritySocketBind, true}}, 1, {"network_events"}, 1, {{"trace.PktMeta", "metadata"}}}, 
    {sys32undefined, DNS_REQUEST, "dns_request", NULL, '\0', 0, 6, {{UDPSendmsg, true}, {UDPDisconnect, true}, {UDPDestroySock, true}, {UDPv6DestroySock, true}, {InetSockSetState, true}, {TCPConnect, true}}, 1, {"network_events"}, 2, {{"trace.PktMeta", "metadata"}, {"[]trace.DnsQueryData", "dns_questions"}}}, 
    {sys32undefined, DNS_RESPONSE, "dns_response", NULL, '\0', 0, 6, {{UDPSendmsg, true}, {UDPDisconnect, true}, {UDPDestroySock, true}, {UDPv6DestroySock, true}, {InetSockSetState, true}, {TCPConnect, true}}, 1, {"network_events"}, 2, {{"trace.PktMeta", "metadata"}, {"[]trace.DnsResponseData", "dns_response"}}}, 
    {sys32undefined, PROC_CREATE, "proc_create", NULL, '\0', 0, 1, {{ProcCreate, true}}, 0, {}, 2, {{"char*", "name"}, {"void*", "proc_ops_addr"}}}, 
    {sys32undefined, KPROBE_ATTACH, "kprobe_attach", NULL, '\0', 0, 2, {{RegisterKprobe, true}, {RegisterKprobeRet, true}}, 0, {}, 3, {{"char*", "symbol_name"}, {"void*", "pre_handler_addr"}, {"void*", "post_handler_addr"}}}, 
    {sys32undefined, CALLUSER_MODE_HELPER, "call_usermodehelper", NULL, '\0', 0, 1, {{CallUsermodeHelper, true}}, 0, {}, 4, {{"constchar*", "pathname"}, {"constchar*const*", "argv"}, {"constchar*const*", "envp"}, {"int", "wait"}}}, 
    {sys32undefined, DEBUG_FS_CREATE_FILE, "debugfs_create_file", NULL, '\0', 0, 1, {{DebugfsCreateFile, true}}, 0, {}, 4, {{"constchar*", "file_name"}, {"constchar*", "path"}, {"mode_t", "mode"}, {"void*", "proc_ops_addr"}}}, 
    {sys32undefined, PRINT_SYSCALL_TABLE, "print_syscall_table", NULL, 1, 0, 1, {{PrintSyscallTable, true}}, 0, {}, 2, {{"unsignedlong[]", "syscalls_addresses"}, {"unsignedlong", "ContextArgName"}}}, 
    {sys32undefined, DEBUG_FS_CREATE_DIR, "debugfs_create_dir", NULL, '\0', 0, 1, {{DebugfsCreateDir, true}}, 0, {}, 2, {{"constchar*", "name"}, {"constchar*", "path"}}}, 
    {sys32undefined, DEVIC_EADD, "device_add", NULL, '\0', 0, 1, {{DeviceAdd, true}}, 0, {}, 2, {{"constchar*", "name"}, {"constchar*", "parent_name"}}}, 
    {sys32undefined, REGISTER_CHRDEV, "register_chrdev", NULL, '\0', 0, 2, {{RegisterChrdev, true}, {RegisterChrdevRet, true}}, 0, {}, 4, {{"unsignedint", "requested_major_number"}, {"unsignedint", "granted_major_number"}, {"constchar*", "char_device_name"}, {"structfile_operations*", "char_device_fops"}}}, 
    {sys32undefined, SHARED_OBJECT_LOADED, "shared_object_loaded", NULL, '\0', 0, 0, {}, 5, {"lsm_hooks", "fs", "fs_file_ops", "proc", "proc_mem"}, 5, {{"constchar*", "pathname"}, {"int", "flags"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}, {"unsignedlong", "ctime"}}}, 
    {sys32undefined, DOINIT_MODULE, "do_init_module", NULL, '\0', 0, 2, {{DoInitModule, true}, {DoInitModuleRet, true}}, 0, {}, 7, {{"constchar*", "name"}, {"constchar*", "version"}, {"constchar*", "src_version"}, {"void*", "prev"}, {"void*", "next"}, {"void*", "prev_next"}, {"void*", "next_prev"}}}, 
    {sys32undefined, SOCKET_ACCEPT, "socket_accept", NULL, 0, 0, 2, {{SyscallEnter__Internal, true}, {SyscallExit__Internal, true}}, 0, {}, 3, {{"int", "sockfd"}, {"structsockaddr*", "local_addr"}, {"structsockaddr*", "remote_addr"}}}, 
    {sys32undefined, LOADEL_FPHDRS, "load_elf_phdrs", NULL, '\0', 0, 1, {{LoadElfPhdrs, true}}, 1, {"proc"}, 3, {{"constchar*", "pathname"}, {"dev_t", "dev"}, {"unsignedlong", "inode"}}}, 
    {sys32undefined, HOOKED_PROC_FOPS, "hooked_proc_fops", NULL, '\0', 0, 1, {{SecurityFilePermission, true}}, 0, {}, 1, {{"[]trace.HookedSymbolData", "hooked_fops_pointers"}}}, 
    {sys32undefined, PRINT_NET_SEQ_OPS, "print_net_seq_ops", NULL, 0, 0, 1, {{PrintNetSeqOps, true}}, 0, {}, 2, {{"unsignedlong[]", "net_seq_ops"}, {"unsignedlong", "ContextArgName"}}}, 
    {sys32undefined, TASK_RENAME, "task_rename", NULL, '\0', 0, 1, {{TaskRename, true}}, 1, {"proc"}, 3, {{"constchar*", "old_name"}, {"constchar*", "new_name"}, {"int", "syscall"}}}, 
    {sys32undefined, SECURITY_INODE_RENAME, "security_inode_rename", NULL, '\0', 0, 1, {{SecurityInodeRename, true}}, 0, {}, 2, {{"constchar*", "old_path"}, {"constchar*", "new_path"}}}, 
    {sys32undefined, DOSIG_ACTION, "do_sigaction", NULL, '\0', 0, 1, {{DoSigaction, true}}, 1, {"proc"}, 11, {{"int", "sig"}, {"bool", "is_sa_initialized"}, {"unsignedlong", "sa_flags"}, {"unsignedlong", "sa_mask"}, {"u8", "sa_handle_method"}, {"void*", "sa_handler"}, {"bool", "is_old_sa_initialized"}, {"unsignedlong", "old_sa_flags"}, {"unsignedlong", "old_sa_mask"}, {"u8", "old_sa_handle_method"}, {"void*", "old_sa_handler"}}}, 
};

#endif

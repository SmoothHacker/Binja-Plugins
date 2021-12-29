import sys
from itertools import chain
from traceback import print_exc
from binaryninja import interaction
from binaryninja import binaryview

from binaryninja.binaryview import BinaryView, BinaryViewType
from binaryninja.enums import LowLevelILOperation
from binaryninja.log import log_error
from binaryninja.plugin import PluginCommand

# x86_64 syscall table
syscall_table = ["read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","pread","pwrite","readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl","dup","dup","pause","nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown","bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve","exit","wait","kill","uname","semget","semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir","fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount","swapon","swapoff","reboot","sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid","readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr","fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents","io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents","set_tid_address","restart_syscall","semtimedop","fadvise","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime","clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat","mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect","ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept","signalfd","eventfd","epoll_create","dup","pipe","inotify_init","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module","sched_setattr","sched_getattr","renameat","seccomp","getrandom","memfd_create","kexec_file_load","bpf","execveat","userfaultfd","membarrier","mlock","copy_file_range","preadv","pwritev","pkey_mprotect","pkey_alloc","pkey_free","statx","io_pgetevents","rseq"]

def print_syscalls(bv):
	# Print Syscall numbers for a provided file
	calling_convention = bv.platform.system_call_convention
	if calling_convention is None:
		log_error('Error: No syscall convention available for {:s}'.format(bv.platform))
		return

	register = calling_convention.int_arg_regs[0]

	report = "### Syscalls for {}\n".format(bv.file.filename)

	for func in bv.functions:
		syscalls = (il for il in chain.from_iterable(func.low_level_il)
					if il.operation == LowLevelILOperation.LLIL_SYSCALL)
		for il in syscalls:
			value = func.get_reg_value_at(il.address, register).value
			report += "##### System call address: [{:#x}](binaryninja://?expr={:#x}) - {}\n".format(il.address, il.address, syscall_table[value])

	if len(report) == 0:
		return "# No Syscalls Discovered in binary"
	return report

def display_syscalls(bv):
	bv.show_markdown_report("Syscall Info Report", print_syscalls(bv))


PluginCommand.register("Syscall Finder", "Shows information about all the syscalls in the binary", display_syscalls)

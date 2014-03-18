System Call Hooker
==================

A linux module that demonstrates how to find out the address of system call table and hook up a system call.

Usage
-----
1. Make sure the kernel headers are installed (`apt-get install linux-headers-$(uname -r)`)
2. `$ make`
3. `insmod ./hooker.ko`
4. operate your system as usual
5. `rmmod ./hooker.ko`
6. the counts of invoking a particular system call will be shown in dmesg.

Know-how
--------

# Description
Merwall is a lightweight Linux firewall, built as Loadable Kernel Module and a userspace administration tool.<br/>

It is based on the Netfilter API for packet filtering and rule matching. Sysfs virtual filesystem is used for communication between userspace and kernelspace.

# Build and launch
$ make<br/>
$ sudo insmod kmerwall.ko

# Remove
$ sudo rmmod kmerwall<br/>
$ make clean

# Examples

* Drop all UDP traffic:
 * ./merwall_admin --proto UDP
* Drop all UDP traffic to/from port 53.
 * ./merwall_admin --proto UDP --dstport 53
* Allow all TCP traffic coming from 1.2.3.4:80
 * ./merwall_admin --action PASS --proto TCP --direction IN --srcip 1.2.3.4 --srcport 80
* Allow outgoing traffic to port 80
 * ./merwall_admin --action PASS --dstport 80
* Delete rule number 33
 * ./merwall_admin --delete 33
* List all rules.
 * ./merwall_admin --list
<br/>
# ToDo
Update documentation: Installation, usage etc.,<br/>

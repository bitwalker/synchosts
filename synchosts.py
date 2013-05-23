#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This script will synchronize host file
# entries in /etc/hosts for a given VM
# in the local Parallel's VM library.

# Import the Parallels Python API
import prlsdkapi
# Other imports
import os
import sys
import re
import tempfile
from optparse import OptionParser

# Parallels constants
consts = prlsdkapi.prlsdk.consts

# Simple exception class for halting the program


class Halt(Exception):
    pass

# Debugging facilities
ENABLE_DEBUGGING = False
# Flag indicating whether to look for and update dnsmasq.conf
UPDATE_DNSMASQ_ENTRIES = False
# Print a debugging message if ENABLE_DEBUGGING is true
# @param message: The message to print
# @param objs: Additional objects to print out


def debug(message, *objs):
    if ENABLE_DEBUGGING is True:
        print message
        for obj in objs:
            print "\n{0}\n".format(obj)

# Login to Parallels Service
# @param server: A new instance of the prlsdkapi.Server class


def login(server):
    try:
        result = server.login_local('', 0, consts.PSL_NORMAL_SECURITY).wait()
    except prlsdkapi.PrlSDKError, e:
        print "Login error: %s" % e
        raise Halt
    return result.get_param()

# Fetch the given VM by name
# @param server: An instance of prlsdkapi.Server
# @param vm_name: The name of the virtual machine to fetch


def get_vm(server, vm_name):
    # Attempt to get a list of VMs
    try:
        result = server.get_vm_list().wait()
    except prlsdkapi.PrlSDKError, e:
        print "Error: %s" % e
        return
    # Iterate through all VMs until we find the one we're looking for
    for i in range(result.get_params_count()):
        vm = result.get_param_by_index(i)
        name = vm.get_name()
        if name.startswith(vm_name):
            return vm
    print "Virtual machine '%s' not found." % vm_name

# Fetch the VmGuest object for a given VM
# @param vm: The VmHost instance to login to
# @param user: Username to login with
# @param password: Password to login with


def get_guest(vm, user, password):
    try:
        guest = vm.login_in_guest(user, password).wait()
    except prlsdkapi.PrlSDKError, e:
        print "Error: %s" % e
        return
    return guest.get_param()

# Fetch the network info for a given VmGuest
# @param guest: The VmGuest instance to fetch network information from


def get_guest_netinfo(guest):
    server_config   = guest.get_network_settings().wait().get_param()
    count           = server_config.get_net_adapters_count()
    vm_net_adapters = {}

    # For every adapter, parse out it's network info
    for n in range(count):
        vm_net_adapters[n]  = {}
        host_net            = server_config.get_net_adapter(n)
        emulated_type       = host_net.get_net_adapter_type()
        type                = ""

        # Determine what type of adapter this is
        if emulated_type == prlsdkapi.prlsdk.consts.PNA_HOST_ONLY:
            type = "host-only"
        elif emulated_type == prlsdkapi.prlsdk.consts.PNA_SHARED:
            type = "shared"
        elif emulated_type == prlsdkapi.prlsdk.consts.PNA_BRIDGED_ETHERNET:
            type = "bridged"

        # Adapter type
        vm_net_adapters[n]["type"]      = type
        # The IPv4 address associated with this adapter
        vm_net_adapters[n]["ip"]        = host_net.get_net_addresses().get_item(1)
        # The hardware address for this adapter
        vm_net_adapters[n]["mac"]       = host_net.get_mac_address()
        # Parse the DNS servers used by this adapter
        dns_str_list                    = host_net.get_dns_servers()
        vm_net_adapters[n]["dns"]       = [dns_str_list.get_item(m) for m in range(dns_str_list.get_items_count())]
        # The gateway address for this adapter
        vm_net_adapters[n]["gateway"]   = host_net.get_default_gateway()

    return vm_net_adapters

# Determine if the given path exists
# @param path: The path to test


def path_exists(path):
    try:
        with open(path):
            return True
    except IOError:
        return False

# Update hosts file
# @param ip: The new host address


def update_hosts(ip):
    # Open the /etc/hosts file, read each line in to memory
    hosts = open('/etc/hosts', 'r')

    debug("Successfully opened /etc/hosts for reading.")

    lines = []
    for line in hosts:
        host = line.split()[1:]
        # If hostname ends with .local or begins with local., then update it's host entry
        if len(host) == 1 and (host[0].find(".local") != -1 or host[0].find("local.") != -1):
            hostname = host[0]
            lines.append(ip + "      " + hostname + "\n")
        # Otherwise, preserve the current entry
        else:
            lines.append(line)
    # Close out hosts
    hosts.close()

    debug("Finished reading /etc/hosts. Closed file.")

    # Write the new hosts to a temporary hosts file
    debug("Writing modified hosts file to temp file")
    temp_hosts = tempfile.NamedTemporaryFile(delete=False)
    temp_hosts.writelines(lines)

    # Overwrite the old hosts file, this will prompt the user for superuser credentials
    debug("Overwriting /etc/hosts, requesting elevation of privileges...")
    os.system('sudo mv ' + temp_hosts.name + ' /etc/hosts')

    # Close the temp hosts file and delete it
    temp_hosts.close()
    debug("Temp file has been closed and deleted")


# Update dnsmasq.conf at the given path
# @param path: The dnsmasq.conf file path
# @param ip: The new host address


def update_dnsmasq_conf(path, ip):
    # Open the /etc/hosts file, read each line in to memory
    dnsmasq = open(path, 'r')

    debug("Successfully opened " + path + " for reading.")

    lines = []
    for line in dnsmasq:
        host = line.split('/')[1:]
        # If hostname ends with .local or begins with local., then update it's dnsmasq entry
        if len(host) == 2 and (host[0].find(".local") != -1 or host[0].find("local.") != -1):
            hostname = host[0]
            lines.append("address=/" + hostname + "/" + ip + "\n")
        # Otherwise, preserve the current entry
        else:
            lines.append(line)
    # Close out dnsmasq.conf
    dnsmasq.close()

    debug("Finished reading " + path + ". Closed file.")

    # Write the new hosts to a temporary hosts file
    debug("Writing modified dnsmasq.conf file to temp file")
    temp_dnsmasq = tempfile.NamedTemporaryFile(delete=False)
    temp_dnsmasq.writelines(lines)

    # Overwrite the old dnsmasq.conf file, this will prompt the user for superuser credentials
    debug("Overwriting " + path + ", requesting elevation of privileges...")
    os.system('sudo mv ' + temp_dnsmasq.name + ' ' + path)

    # Close the temp hosts file and delete it
    temp_dnsmasq.close()
    debug("Temp file has been closed and deleted")


# The main entry point for our application
# @param vmname: The name of the VM to synchronize with
# @param username: The username to login to the VM with
# @param password: The password to login to the VM with


def main(vmname, username, password):
    debug("Synchronizing host entries for {0} as {1}:{2}".format(vmname, username, password))
    # Init Parallels SDK lib
    prlsdkapi.init_desktop_sdk()
    # For Win/Linux, this script will take a little tweaking
    # but to start with, you'll need to uncomment the following
    # prlsdkapi.init_desktop_wl_sdk()

    # Create server object and login
    server = prlsdkapi.Server()
    login(server)

    debug("Logged in to Parallels.")

    # Find vm
    vm = get_vm(server, vmname)

    if (vm):
        debug("Successfully fetched VM with name %s" % vmname)

        # Get guest object
        guest = get_guest(vm, username, password)

        # Get guest network info
        network_info = get_guest_netinfo(guest)

        debug("Acquired the following network information:", network_info)

        # Extract the guest IP address
        m = re.search('^([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', network_info[0]["ip"])
        ip = m.group(0)

        debug("Selected %s as the new host IP address." % ip)

        # Update hosts file
        update_hosts(ip)

        # If flag is set, update dnsmasq.conf
        if (UPDATE_DNSMASQ_ENTRIES):
            dnsmasq_found = False
            debug("Searching for dnsmasq.conf...")
            if (path_exists("/etc/dnsmasq.conf")):
                debug("Found dnsmasq.conf in /etc")
                dnsmasq_found = True
                update_dnsmasq_conf("/etc/dnsmasq.conf", ip)
            if (path_exists("/usr/local/etc/dnsmasq.conf")):
                debug("Found dnsmasq.conf in /usr/local/etc/dnsmasq.conf")
                dnsmasq_found = True
                update_dnsmasq_conf("/usr/local/etc/dnsmasq.conf", ip)
            if (dnsmasq_found is False):
                debug("No dnsmasq.conf file found.")

        # Logoff of guest
        guest.logout()
        debug("Logged off of VM guest")
        print "Host file entries for *.local and local.* have been updated!"
        print "New address is: " + ip
    else:
        print "Could not find a VM by the name '%s'" % vmname

    server.logoff()
    prlsdkapi.deinit_sdk()
    debug("Successfully logged out of Parallels and unloaded SDK.")

if __name__ == "__main__":
    # Define CLI options
    parser = OptionParser(usage="%prog [-n] [-u] [-p] [-d]", version="%prog 1.0")
    parser.add_option("-n", "--name", metavar="VMNAME", dest="vmname", help="Name of the VM to load netinfo from")
    parser.add_option("-u", "--user", metavar="USERNAME", dest="username", help="VM username")
    parser.add_option("-p", "--pass", metavar="PASSWORD", dest="password", help="VM password")
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help="Print useful debugging messages and data")
    parser.add_option("-m", "--dnsmasq", action="store_true", dest="using_dnsmasq", help="Set to true if you want to update dnsmasq.conf entries.")

    # Parse provided arguments
    (options, args) = parser.parse_args()
    if options.debug is True:
        ENABLE_DEBUGGING = True
    if options.using_dnsmasq is True:
        UPDATE_DNSMASQ_ENTRIES = True
    if options.vmname is None:
        parser.error("You must provide a valid VM name to target.")
    if options.username is None or options.password is None:
        parser.error("You must provide a valid username and password to login to the VM guest")
    try:
        sys.exit(main(options.vmname, options.username, options.password))
    except Halt:
        pass

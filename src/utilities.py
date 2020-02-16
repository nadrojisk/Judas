import os
import shutil
try:
    import winreg as wr
except ImportError:
    pass
import netifaces
from config import VERBOSE


def get_ip():
    interface = choose_interface()
    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']


def choose_interface():
    """
    Allows user to select interface based
    on system interfaces
    """
    interfaces = netifaces.interfaces()

    if os.name == 'nt':
        # allows windows machines to choose interfaces
        iface_names = ['(unknown)' for i in range(len(interfaces))]
        reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
        reg_key = wr.OpenKey(
            reg, r'SYSTEM\CurrentControlSet\Control\Network\
            {4d36e972-e325-11ce-bfc1-08002be10318}')
        for counter, interface in enumerate(interfaces):
            try:
                reg_subkey = wr.OpenKey(
                    reg_key, interface + r'\Connection')

                iface_names[counter] = wr.QueryValueEx(reg_subkey, 'Name')[0]
            except FileNotFoundError:
                pass
        interfaces = iface_names

    print('Select Interface: ')

    for val, count in enumerate(interfaces):
        print(val, count)

    selection = int(input())

    return interfaces[selection]


def ip_to_hex(ip):
    new_ip = "".join([hex(int(x))[2:].zfill(2) for x in ip.split(".")])

    return bytes.fromhex(new_ip)


def port_to_hex(string):
    return int(string).to_bytes(2, 'big')


def make_duplicate(source, tag=None):
    if VERBOSE:
        print(f"Making duplicate file for {source}")
    if tag:
        tag = "_" + tag
    else:
        tag = "_"

    split_src = source.split('.')
    split_src[-2] += tag
    dest = ".".join(split_src)
    if os.path.exists(dest):
        os.remove(dest)
    shutil.copyfile(source, dest)
    if VERBOSE:
        print(f"New file has been made: {dest}\n")
    return dest

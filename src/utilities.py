import os
import shutil


def ip_to_hex(ip):
    new_ip = "".join([hex(int(x))[2:].zfill(2) for x in ip.split(".")])

    return bytes.fromhex(new_ip)


def port_to_hex(string):
    return int(string).to_bytes(2, 'big')


def make_duplicate(source, tag=None):
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
    return dest

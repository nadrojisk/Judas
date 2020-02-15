import os
import shutil


def make_duplicate(source):
    split_src = source.split('.')
    split_src[-2] += "_"
    dest = ".".join(split_src)
    if os.path.exists(dest):
        os.remove(dest)
    shutil.copyfile(source, dest)
    return dest

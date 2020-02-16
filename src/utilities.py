import os
import shutil


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

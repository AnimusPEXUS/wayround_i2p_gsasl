#!/usr/bin/python3

import subprocess
import os.path


cwd = os.path.dirname(os.path.realpath(__file__))

ret = 0

for pa in [cwd]:

    files = sorted(os.listdir(pa))

    for i in range(len(files) - 1, -1, -1):
        if not files[i].endswith('.pyx'):
            del(files[i])

    print("Running cython on .pyx files in {}".format(pa))

    for i in files:

        i = os.path.join(pa, i)

        i_target = '{}.c'.format(i[:-4])

        is_stat = os.stat(i)
        it_stat = None
        if os.path.isfile(i_target):
            it_stat = os.stat(i_target)

        if it_stat is None or it_stat.st_mtime < is_stat.st_mtime:
            pass
        else:
            continue

        cmd = ['cython', '-3', i]
        print("  {}".format(' '.join(cmd)))
        p = subprocess.Popen(cmd, cwd=pa)
        res = p.wait()

        if res != 0:
            ret = 1
            break

    if ret != 0:
        break

exit(ret)

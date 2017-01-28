#!/usr/bin/env python3
#$#HEADER-START
# vim:set expandtab ts=4 sw=4 ai ft=python:
#
#     Cryptex
#
#     Copyright (C) 2016 Brandon Gillespie
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as published
#     by the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#$#HEADER-END

import sys
import os
import argparse
import doctest
import subprocess
from subprocess import *
import hashlib
import shutil

import rfx
from rfx.test import *

################################################################################
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=['test', 'build', 'push'])
    args = parser.parse_args()


    if args.action == "test":
        if os.path.exists("test.log"):
            os.unlink("test.log")
        tap = TAP()
        tap.lint(".", "cryptex", exit_on_fail=True)
#        subprocess.call("pylint cryptex", shell=True)
   #    tap.inline_unit(cryptex, exit_on_fail=True)
        tap.exit()
    elif args.action == "build":
        res = subprocess.call(["python", "setup.py", "sdist", "bdist_wheel"])
        print(res)
    elif args.action == "push":
        res = subprocess.call("twine upload dist/*", shell=True)

################################################################################
if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""
Created on Tue Nov 14 14:19:42 2023

@author: alex
"""

"""
This py checks file attribution prevent execute it accidentally
"""

import os,sys,stat
import ctypes


def main(file):
    print(file)
    state = os.stat(file)
    mode = state.st_mode
    print(mode)
    os.chmod(file,666)
    print(mode)
    print(1)
    

main(sys.argv[1])
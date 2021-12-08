#!/usr/bin/env python
"""
Usage:  main.py
        main.py [--junctiondir=JUNCTIONDIR]
        main.py [--format=JUNCTIONDIR]
Options:
  --junctiondir=DIR         directory that contains the junctions
  -h --help     Show this screen.

"""
from lib import f_processJunction as f_processJunction
import os
from docopt import docopt
import tkinter
from tkinter import filedialog

root = tkinter.Tk()
root.withdraw()

def main():
    junctiondir = ''
    args = docopt(__doc__)
    print(args)
    if args['--junctiondir']:
        #ok
        junctiondir = args['--junctiondir']
        print(junctiondir)
    if junctiondir == '':
        junctiondir = filedialog.askdirectory(mustexist=True)

    if junctiondir is not None and len(junctiondir) > 0:
        for junctionfilepath in os.listdir(junctiondir):
            print("\n\nOpening file " + junctiondir + "/" + junctionfilepath)
            f_processJunction(junctiondir+"/"+junctionfilepath)

if __name__=='__main__':
   main()

#!/usr/bin/env python
"""
Usage:  main.py
        main.py [--junctiondir=JUNCTIONDIR]

Options:
  --junctiondir=DIR     directory that contains the junctions
  -h --help     Show this screen.

"""
from lib import f_processJunction as f_processJunction
from lib import f_createSampleJunctions as f_createSampleJunctions
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
        _junction_vars = []
        for junctionfilepath in os.listdir(junctiondir):
            print("\n\nOpening file " + junctiondir + "/" + junctionfilepath)
            _junction_vars.append(f_processJunction(junctiondir+"/"+junctionfilepath))

        # create a junctions file that ties everything together
        # the loop removes empty elements from the list
        f_createSampleJunctions([x for x in _junction_vars if x])


if __name__=='__main__':
   main()

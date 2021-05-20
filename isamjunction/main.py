#!/usr/bin/env python
from lib import f_processJunction as f_processJunction
import os
import tkinter
from tkinter import filedialog

root = tkinter.Tk()
root.withdraw()

junctiondir = filedialog.askdirectory(mustexist=True)

if junctiondir is not None and len(junctiondir) > 0:
    for junctionfilepath in os.listdir(junctiondir):
        print("\n\nOpening file " + junctiondir + "/" + junctionfilepath)
        f_processJunction(junctiondir+"/"+junctionfilepath)





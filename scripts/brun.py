import psutil
import subprocess
import time
import re
import argparse
import os
from datetime import datetime

def parseArgs():

    logParser = argparse.ArgumentParser(description='WinAFL assist tool')

    logParser.add_argument('-s',
                           '--startSession',
                           action='store',
                           help='Common args, without in/out dirs')

    logParser.add_argument('-i',
                           '--input',
                           action='store',
                           help='Input corpus')

    logParser.add_argument('-n',
                           '--nThreads',
                           action='store',
                           type=int,
                           default=1,
                           help='Number of threads')

    return logParser.parse_args()

def spawnProc(cmd):
    r = subprocess.Popen(["cmd.exe", "/c", cmd], 
            creationflags=subprocess.CREATE_NEW_CONSOLE)
    return r

def kill(pid):
    print("Killing pid {}".format(pid))
    subprocess.call(['taskkill', '/F', '/T', '/PID', str(pid)])



if __name__ == "__main__":

    args = parseArgs()

    print("Starting session: {}".format(args.startSession))

    # Here we differentiate strategies:
    # inc coverage, bits coverage, hash coverage, cmpcov, strcov
    #
    # If we have 10 threads, let's try:
    # 1 | bits + cmpcov  | most robust | x6
    # 2 | inc + strcov + cmpcov | string match | x2
    # 3 | inc + cmpcov | lots of samples, a bit desperate | x1 
    # 4 | hash + cmpcov | HUGE lots of samples, extremely desperate | x1
    #
    # We run session for 10 minutes, then we stop, minimize the samples to one
    # directory based on bits coverage, and start again.
    # 
    # Meanwhile we sould monitor memory consumption, if one instance exceeds 
    # 100%/nThreads quota - restart it
    type1Params = "--inccov=false"
    type2Params = "--strcmp"
    type3Params = "--bitcov=false"
    type4Params = "--hashcov=true"
    crashDir = "crashes"

    totalMem = psutil.virtual_memory().total
    print("Total mem: {}".format(totalMem))

    cmds = []
    # populate params
    cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
        start = args.startSession, 
        opt = type1Params,
        inp = args.input,
        out = "out_type1",
        crash = crashDir) 
            for i in range(0, 1)]

    cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
        start = args.startSession, 
        opt = type2Params,
        inp = args.input,
        out = "out_type2",
        crash = crashDir) 
            for i in range(0, 1)]

    cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
        start = args.startSession, 
        opt = type3Params,
        inp = args.input,
        out = "out_type3",
        crash = crashDir) 
            for i in range(0, 1)]

    cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
        start = args.startSession, 
        opt = type3Params,
        inp = args.input,
        out = "out_type4",
        crash = crashDir) 
            for i in range(0, 1)]

    pool = []
    restartTime = 0
    try:
        while 1:

            # run session
            if not pool:
                pool = [spawnProc(cmd) for cmd in cmds]
                restartTime = datetime.now()

            # wait 10 minutes & restart session
            timeDiff = datetime.now() - restartTime
            if timeDiff.seconds > 60:
                print("Stopping session...")
                [kill(p.pid) for p in pool]
                restartTime = datetime.now()
                pool = []

            # run cmin

            # restart exceeded limit
            # restart failed?

            time.sleep(1)
        

    except KeyboardInterrupt:
        print("Ctrl-c pressed, killing all the processes")
        [kill(p.pid) for p in pool]

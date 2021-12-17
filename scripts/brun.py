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

    logParser.add_argument('-c',
                           '--scale',
                           action='store',
                           type=int,
                           default=0,
                           help='Number of threads, 1 = 5, 2 = 10...')

    logParser.add_argument('-m',
                           '--memoryLimit',
                           action='store',
                           type=int,
                           default=80,
                           help='If memory is exceeded, the fuzzers restart')

    logParser.add_argument('-r',
                           '--restartTimeout',
                           action='store',
                           type=int,
                           default=10,
                           help='Force restart & cmin in N minutes')

    return logParser.parse_args()

def spawnProc(cmd):
    r = subprocess.Popen(["cmd.exe", "/c", cmd], 
            creationflags=subprocess.CREATE_NEW_CONSOLE)
    return r

def spawnPiped(cmd):
    r = subprocess.Popen(["cmd.exe", "/c", cmd], 
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
            )
    return r

def kill(pid):
    #print("Killing pid {}".format(pid))
    subprocess.call(['taskkill', '/F', '/T', '/PID', str(pid)])

def removeDir(path, nonExistOk = True):
    p = spawnPiped("rmdir /S /Q {}".format(path))
    res, resErr = p.communicate()
    res = str(res)
    resErr = str(resErr)
    p.wait()
    if p.returncode == 2 and nonExistOk:
        return
    if p.returncode != 0:
        print("removeDir: {} code {}, stdout: {}, stderr: {}".format(
            path, p.returncode, res, resErr))
        raise RuntimeError("Can't remove {}: {}".format(path, p.returncode))


def populateParams(inputDir, scale):
    cmds = []
    if scale == 0:
        # test run, only two threads
        cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
            start = args.startSession, 
            opt = type1Params,
            inp = inputDir,
            out = "out\\type1_{}".format(i),
            crash = crashDir) 
            for i in range(0, 2)]
        return cmds
    
    for s in range(0, scale):
        cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
            start = args.startSession, 
            opt = type1Params,
            inp = inputDir,
            out = "out\\type1_{}_{}".format(s, i),
            crash = crashDir) 
            for i in range(0, 2)]

        cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
            start = args.startSession, 
            opt = type2Params,
            inp = inputDir,
            out = "out\\type2_{}_{}".format(s, i),
            crash = crashDir) 
            for i in range(0, 1)]

        cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
            start = args.startSession, 
            opt = type3Params,
            inp = inputDir,
            out = "out\\type3_{}_{}".format(s, i),
            crash = crashDir) 
            for i in range(0, 1)]

        cmds += ["{start} {opt} --in {inp} --out {out} --crash {crash}".format(
            start = args.startSession, 
            opt = type3Params,
            inp = inputDir,
            out = "out\\type4_{}_{}".format(s, i),
            crash = crashDir) 
            for i in range(0, 1)]
    return cmds

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
    print("Total mem: {} GB".format(totalMem / (1024 ** 3)))

    outputDir = "out"
    outputBak = "out_bak"

    try:
        os.mkdir(outputDir)
    except OSError:
        pass

    cmds = populateParams(args.input, args.scale)
    # populate params
    pool = []
    restartTime = 0
    try:
        while 1:

            # run session
            if not pool:
                pool = [{'p': spawnProc(cmd), 'c': cmd} for cmd in cmds]
                restartTime = datetime.now()

            # wait 10 minutes & restart session
            timeDiff = datetime.now() - restartTime
            if timeDiff.seconds > 60 * args.restartTimeout:
                print("Stopping session...")
                [kill(p['p'].pid) for p in pool]
                [p['p'].wait() for p in pool]
                restartTime = datetime.now()
                pool = []

                removeDir(outputBak)
                os.rename(outputDir, outputBak)
                os.mkdir(outputDir)
                cmds = populateParams(outputBak, args.scale)
                pool = []
            else:
                time.sleep(1)

            # resource check 
            mem_info = {}
            for i, p in enumerate(pool):
                pid = p['p'].pid

                try:
                    cp = psutil.Process(pid)
                except psutil.NoSuchProcess:
                    continue
                mem = cp.memory_percent()
                for child in cp.children(recursive=True):
                    mem += child.memory_percent()
                mem_info[pid] = mem

            mi_sorted = [k for k, v in sorted(mem_info.items(), 
                key=lambda item: item[1])]

            mem_usage = psutil.virtual_memory().percent
            print("Mem usage: {}".format(mem_usage))
            if mem_usage > args.memoryLimit:
                tgt_pid = mi_sorted[-1]
                print("Restarting pid: {}".format(tgt_pid))
                idx = 0
                for i, p in enumerate(pool):
                    if p['p'].pid == tgt_pid:
                        idx = i
                cmd = pool[idx]['c']
                kill(tgt_pid)
                pool[idx]['p'].wait()
                pool[idx] = {'p': spawnProc(cmd), 'c': cmd}

    except KeyboardInterrupt:
        print("Ctrl-c pressed, killing all the processes")
        [kill(p['p'].pid) for p in pool]

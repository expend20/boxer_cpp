
# Fuzzing example

To illustrate something more real world, let's try to fuzz the "png" codec

1) Get the harness.

Harnesses are kept in another repo. `https://git.tw1st.link/expy/drills`. 
It's yet another fuzzer I played with some time ago, in order to build it you 
need DynamoRIO locally. 
```
cmake .. -DDynamoRIO_DIR=..drdir\cmake && cmake --build . --config RelWithDebInfo
```
This will give you `HarnessWicLib.dll` harness for windowscodecs.dll

2) Get the basicblocks offsets.

Fuzzer has different mode of discovering basicblocks during instrumentation. 
The most robust one is to use IDA and dump all the address with 
`boxer_cpp\scripts\bbs_ida.py`. Open `windowscodecs.dll` in IDA, run the script 
`bbs_ida.py` after the auto analysis finish, and get `WindowsCodecs.dll.bbs`.

3) Finally run the fuzzer:
```
RelWithDebInfo\boxer_veh.exe --inst_bbs_file=z:\dll\WindowsCodecs.dll.bbs.64 --cov windowscodecs.dll --dll HarnessWicLib.dll --init_func initPng --func fuzzIteration --zero_corp_sample_size=512 --mutator_density=32
```
This should start producing samples into `out_auto_initPng_windowscodecs.dll` 
output directory. 

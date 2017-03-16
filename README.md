# Summary
This is a simple fuzzer based on ASAN address sanitizer and code coverage.
Test programs must be compiled with the following command and accept a binary file as input.
```shell
clang -fsanitize=address -fsanitize-coverage=bb
```

## 1. Init
```shell
randomFuzz.py init --dir=test --cmd="asn1Parser %s"
```
Prepares the state directory "test" for the asn1Parser.

## 2. Select testacases                                                        
```shell
randomFuzz.py select-testcases  --dir=test /path/to/seeds
```

This programm will test the cmd on all files in testdir.
It will select the testcases with the best coverage and save them to seed-min-%d.ext.
Files are all needed binaries and config files, that are needed to execute the cmd.

## 3. Start Master
```shell
randomFuzz.py fuzz --dir=workdir --port=1337
```

Prepares the Fuzzing master proces, that keeps track of testcases and crashes.
It will pass all necessary information to the worker, that will execute the testcases and cycle through all seeds

## 4. Start Worker
```shell
randomFuzz.py work --dir=workdir --ip=ip ports
```
The worker will fetch all needed files from the master and starts mutating them in a randomly and update the master.
All ports provided to the worker will be served in a round robin schedule.

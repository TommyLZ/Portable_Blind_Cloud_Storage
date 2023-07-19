# Portable Blind Cloud Storage
This repository contains a reference implementation of IPBCS (Myscheme): Improved Portable Blind Cloud Storage Scheme against Compromised Servers. And the C++ implementation of the references [PHE](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-lai.pdf) and [PBCS](https://www.usenix.org/system/files/sec22-chen-long.pdf). The code in this repository can be used to reproduce the experimental results from Section 7 of the paper.

WARNING: This is an academic prototype, and should not be used in applications without code review.

## How to run
### Dependencies
- Crypto++ 8.6.0
- PBC 0.5.14
### Running the repo
Clone this repo. Make sure `g++` and `cmake` have been installed. (Linux) \
Build and run the experiment locally.
```
cd Build
cmake ..
make
./build < ../Param/a.param
```
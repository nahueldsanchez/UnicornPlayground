# Playing with Unicorn, Capstone and Keystone engine. Solving PicoCTF 2018 assembly-0 and assembly-1 challenges

## Installing unicorn engine (CPU emulator framework) on Ubuntu 18.04.1 LTS

Steps based on [1].

1) sudo apt-get install libglib2.0-dev
2) git clone https://github.com/unicorn-engine/unicorn.git
3) cd unicorn
4) ./make.sh
5) export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:</path_where_libunicorn.so.1_is_stored>
6) ./samples/sample_all.sh #Samples should run without problems

At this point we've installed unicorn engine core. Let's install the Python binding:

7) create virtualenv and activate it
8) cd bindings/python
9) make
10) python setup.py install
11) ./sample_x86.py #Samples should run without problems

caca


Now we've everything installed.

## Installing keystone engine (The Ultimate Assembler Framework) on Ubuntu 18.04.1 LTS

As prerequisite cmake must be installed in the target system.

1) git clone https://github.com/keystone-engine/keystone.git
2) cd keystone/
3) mkdir build
4) cd build/
5) ../make-share.sh
6) export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path_to_keystone>/build/llvm/lib/
7) We'll test if installation was successful. 
8) cd kstool
9) ./kstool x32 "add eax, ebx", should return add eax, ebx = [ 01 d8 ]

Now, we'll install Python bindings:

10) create virtualenv and activate it (Or better, use the previously created virtualenv)
11) pip install keystone-engine
12) To test it run python and try to import keystone (from keystone import *)


## Installing Capstone engine (The Ultimate Disassembler) on Ubuntu 18.04.1 LTS

1) git clone https://github.com/aquynh/capstone.git
2) cd capstone
3) ./make.sh
4) export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:</path_where_libcapstone.so.4_is_stored>
5) We've installed Capstone successfully. Let's test it.
6) Go to Capstone installation directory ./test subdirectory.
7) Execute some tests, everything should run flawlessly.

Now, we'll install the Python binding:

8) create virtualenv and activate it (Or better, use the previously created virtualenv)
9) pip install capstone
10) To test it run python and execute: from capstone import *

## Setting up the virtualenv

I've added the following lines to the "activate" file to avoid executing them every time I've to use the tools:

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:</path_where_libcapstone.so.4_is_stored>

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path_to_keystone>/build/llvm/lib/

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:</path_where_libunicorn.so.1_is_stored>

## Solving the challenges

Once we've everything installed we'll be able to "run" the provided assembly code and luckily answer the following
question. What's stored in EAX at the end of the execution?

To answer that (and justify installing all the tools too :P) I've created two Python scripts that perform two tasks:

1) First they take assembly code and translates it to machine code.
2) It takes the previously obtained machine code and emulates it using Unicorn Engine.

Once the emulation is completed the scripts print the value of the EAX register.

You can find two folders picoCTF2018_assembly-0 and picoCTF2018_assembly-1
which contain the Python scripts to solve both challenges. I've added some hooks
to understand how to use this functionality as it be useful for other tasks.

I've also had to modify the provided assembly a little bit to be able to emulate it.

I've performed the following changes:
1) added some push instructions at the beginning to pass the arguments to the functions
2) added some fake return address (push 0x00) to align the stack
3) removed the ret instruction in assembly-1 as the emulation tried to continue once all the provided code was already executed.



## References

[1] https://github.com/unicorn-engine/unicorn/wiki/quick-start
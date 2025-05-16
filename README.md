# Hermes: Efficient and Secure Multi-Writer Encrypted Database

![x86](https://github.com/vt-asaplab/Hermes/blob/main/Hermes/workflows/x86/badge.svg)
![arm](https://github.com/vt-asaplab/Hermes/blob/main/Hermes/workflows/arm/badge.svg)

This is our full implementation for our [Hermes paper](https://eprint.iacr.org/2025/701).

**WARNING**: This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

# Required Libraries

1. [GMP](https://gmplib.org)

2. [PBC](https://crypto.stanford.edu/pbc)

3. [ZeroMQ](https://github.com/zeromq/cppzmq)

4. [EMP-Toolkit](https://github.com/emp-toolkit/emp-tool)

You can run the script file **auto_setup.sh** to automatically install the required libraries. 
```
./auto_setup.sh
```

# Dataset

Download Enron email dataset at: https://www.cs.cmu.edu/~enron/, then extract to obtain **maildir** folder. Put file ``extract_database.go`` on the same hierarchy level as **maildir**. Next, execute ``extract_database.go`` to obtain folder **database** as follows, then move it into **Hermes** on the same level as folders **server** and **client**. 
```
go env -w GO111MODULE=off 
go get github.com/montanaflynn/stats
go run extract_database.go
```

# Build & Compile

Go to the folder **Hermes** then execute:
``` 
make clean
make
```
This is going to create executable files *server* in **server** folder and *client* in **client** folder.

## Testing

1. Launch server:
```
cd server
./server [<Number_of_Writers>]
```

For example, we launch server with 150 writers:
```
./server 150
```

By default without an input parameter, the server is initialized with 25 writers. 

2. Launch client:

For keyword search:
```
cd client
./client -s [<keyword>] [<writer_subset_size>] 
```

For keyword update:
```
cd client
./client -u [<number_of_updates>]
```

For example: 
```
./client -s university 150    // Search keyword "university" over databases of 150 writers
```

```
./client -u 150               // Update 150 new keywords
```

**NOTE**: We only need to start server one time. 

## Enable Hermes<sup>+</sup>
Uncomment the line 21 ``#define SEARCH_EFFICIENCY       1`` in file config.hpp and recompile.

## Configuring Number of Threads
Change the constants defined at lines 4 and 5: ``const int MAX_THREADS_INIT      = 8;`` and ``const int MAX_THREADS_SEARCH      = 8;`` in file **config.hpp** and recompile server. 
``` 
make server
```

## Configuring Server IP Address
To run experiments with a remote server, we need to change the IP loopback ```127.0.0.1``` to the IP address of the server as follows. 

Modify the server's IP address at line 682 ``string server_address = "tcp://127.0.0.1:" + to_string(SERVER_PORT);`` in file **client/client.cpp** and recompile client.
``` 
make client
```

## Citing

If the code is found useful, we would be appreciated if our paper can be cited with the following bibtex format: 

```
@inproceedings{le2025hermes,
author = {Le, Tung and  Hoang, Thang},
title = {{Hermes: Efficient and Secure Multi-Writer Encrypted Database}},
booktitle = {46th IEEE Symposium on Security and Privacy (IEEE S&P 2025)},
year = {2025},
pages = {2642-2661},
address = {San Francisco, CA, USA},
month = {May},
year = {2025}
}
```

# Further Information
For any inquiries, bugs, and assistance on building and running the code, please contact me at [tungle@vt.edu](mailto:tungle@vt.edu?Subject=[Hermes]%20Inquiry).

<img src="https://github.com/vt-asaplab/Hermes/blob/main/Hermes/workflows/hermes-icon.jpg" height="150">

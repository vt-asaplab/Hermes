#!/bin/bash

# Update system 
sudo apt-get update

# Install build tools
sudo apt-get install -y build-essential

# Install ZeroMQ
sudo apt-get install -y libzmq3-dev

# Install libssl, libtool, m4, etc.
sudo apt-get install -y autogen automake ca-certificates cmake git libboost-dev libboost-thread-dev libsodium-dev libssl-dev libtool m4 texinfo yasm flex bison

# Create folder Hermes where libraries are installed
mkdir /home/$USER/Hermes

# Install Golang
wget https://go.dev/dl/go1.17.7.linux-amd64.tar.gz 
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.17.7.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin/
echo 'export PATH=$PATH:/usr/local/go/bin/' >> /home/$USER/.bashrc
go env -w GO111MODULE=off
go get github.com/montanaflynn/stats

# Install ZeroMQ
wget https://github.com/zeromq/cppzmq/archive/refs/tags/v4.10.0.tar.gz
tar -xvf v4.10.0.tar.gz
cd cppzmq-4.10.0/
mkdir build
cd build/ 
cmake -DCMAKE_INSTALL_PREFIX:PATH=/home/$USER/Hermes ..
make -j8
make install 
cd ../..

# Install GMP 
export LDFLAGS="-L/home/$USER/Hermes/lib/"
export CPPFLAGS="-I/home/$USER/Hermes/include"
wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
tar -xvf gmp-6.3.0.tar.xz
cd gmp-6.3.0/
./configure --prefix=/home/$USER/Hermes/
make -j8
make install 
cd ..

# Install PBC
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14/
./configure --prefix=/home/$USER/Hermes/
make -j8
make install 
cd ..

# Install EMP-Toolkit
wget https://github.com/emp-toolkit/emp-tool/archive/refs/tags/0.2.5.tar.gz
tar -xvf 0.2.5.tar.gz 
cd emp-tool-0.2.5/
cmake -DCMAKE_INSTALL_PREFIX:PATH=/home/$USER/Hermes .
make -j8
make install 
cd ..

wget https://github.com/emp-toolkit/emp-ot/archive/refs/tags/0.2.4.tar.gz
tar -xvf 0.2.4.tar.gz 
cd emp-ot-0.2.4/
cmake -DCMAKE_INSTALL_PREFIX:PATH=/home/$USER/Hermes .
make -j8
make install 
cd ..

git clone https://github.com/emp-toolkit/emp-agmpc
cd emp-agmpc 
cmake -DCMAKE_INSTALL_PREFIX:PATH=/home/$USER/Hermes .
make -j8
make install 
cd ..

# Set library path
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/$USER/Hermes/lib/
echo 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/$USER/Hermes/lib/' >> /home/$USER/.bashrc

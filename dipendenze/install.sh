cd Build/polarssl-0.12.1
make all
sudo make install
cd ..

cd pth-2.0.7
./configure
make all
sudo make install
cd ..

cd zlogger-1.1.2
./configure
make all
sudo make install
cd ..

cd eibnetmux-1.9.14
./configure
make all
cd eibnetmux
make all
cd ..

cd client_lib
make

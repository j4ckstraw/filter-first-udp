# compile
make
# install
sudo insmod filter.ko
# check if it works
dmesg -w -k
# uninstall
sudo rmmod filter.ko

happy to use it :D

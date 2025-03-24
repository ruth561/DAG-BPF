#!/bin/bash

dmesg -C
insmod dag_bpf.ko

echo "[*] insmod dag_bpf.ko"
dmesg
dmesg -C

./bpf &
echo "[*] ./bpf &"

sleep 0.5

echo "[*] cat /sys/kernel/my_ops/ctl"
cat /sys/kernel/my_ops/ctl
echo "---------- dmesg ----------"
dmesg
dmesg -C
echo "------- trace_pipe --------"
timeout 1 cat /sys/kernel/tracing/trace_pipe

sleep 0.5
pkill bpf
sleep 0.5

rmmod dag_bpf

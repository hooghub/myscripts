#!/bin/bash
# Simple sysinfo script

echo "================= 基础系统信息 ================="
echo "主机名:        $(hostname)"
echo "操作系统:      $(. /etc/os-release; echo $PRETTY_NAME)"
echo "内核版本:      $(uname -r)"
echo "架构:          $(uname -m)"
echo "运行时间:      $(uptime -p)"
echo

echo "================= CPU 信息 ================="
echo "CPU 型号:      $(awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo)"
echo "CPU 核心数:    $(nproc)"
echo "CPU 架构:      $(lscpu | grep 'Architecture' | awk '{print $2}')"
echo

echo "================= 内存信息 ================="
free -h
echo

echo "================= 硬盘信息 ================="
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT
echo
df -h --total | grep -E "total|Filesystem"
echo

echo "================= 网络信息 ================="
ip -4 a | grep inet | awk '{print $2,$NF}'
[ -f /proc/net/if_inet6 ] && ip -6 a | grep inet6 | awk '{print $2,$NF}'
echo

echo "================= 进程负载 ================="
uptime
echo

echo "================= 虚拟化信息 ================="
virt=$(systemd-detect-virt 2>/dev/null)
[ "$virt" = "none" ] && virt="物理机"
echo "虚拟化类型:    $virt"
echo

echo "================= 完成 ================="

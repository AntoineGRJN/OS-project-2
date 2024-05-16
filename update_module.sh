if make; then
    sudo rmmod memory_info.ko
    sudo insmod memory_info.ko    
    dmesg | tail -n 50
fi
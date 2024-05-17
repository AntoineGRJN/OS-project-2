if make; then
    sudo rmmod memory_info_os.ko
    sudo insmod memory_info_os.ko    
    dmesg | tail -n 50
fi
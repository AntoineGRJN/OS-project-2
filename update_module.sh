if make; then
    sudo rmmod module_project_os.ko
    sudo insmod module_project_os.ko    
    dmesg | tail -n 50
fi
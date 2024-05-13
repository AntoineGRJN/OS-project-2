#include<linux/fs.h>        // file operations
#include<linux/proc_fs.h>   // proc_create, proc_ops
#include<linux/uaccess.h>   // copy_from_user, copy_to_user
#include<linux/init.h>      // kernel initialization
#include<linux/seq_file.h>  // seq_read, seq_lseek, single_open, single_release
#include<linux/module.h>    // all modules need this
#include<linux/slab.h>      // memory allocation (kmalloc/kzalloc)
#include<linux/kernel.h>    // kernel logging

#define DEV_NAME "module_info0940" // name of the proc entry

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Creates /proc entry with read/write functionality.");

static char *message = NULL;

// this function converts a string to uppercase
void strtoupper(char *str) {
    while (*str) {
        if (*str > 'a' && *str < 'z')
            *str -= ('a'-'A');
        str++;
    }
}

// this function writes a message to the pseudo file system
static ssize_t write_msg(struct file *file, const char __user *buff, size_t cnt, loff_t *f_pos){

    // allocate memory, (size and flag) - flag: type of memory (kernel memory)
    char *tmp = kzalloc(cnt + 1, GFP_KERNEL);
    if(!tmp){
        return -ENOMEM;
    }

    // copy data from user space to kernel space by using copy_from_user
    if(copy_from_user(tmp, buff, cnt)){
        kfree(tmp);
        return -EFAULT;
    }

    if (message){
        kfree(message);
    }
    // Convert lowercases to uppercases
    strtoupper(tmp);
    message=tmp;
    return cnt;
}

// this function reads a message from the pseudo file system via the seq_printf function
static int show_the_proc(struct seq_file *a, void *v){
    seq_printf(a,"%s\n",message);
    return 0;
}

// this function opens the proc entry by calling the show_the_proc function
static int open_the_proc(struct inode *inode, struct file *file){
    return single_open(file, show_the_proc, NULL);
}

/*-----------------------------------------------------------------------*/
// Structure that associates a set of function pointers (e.g., device_open)
// that implement the corresponding file operations (e.g., open).
/*-----------------------------------------------------------------------*/
static struct file_operations new_fops={ //defined in linux/fs.h
    .owner = THIS_MODULE,
    .open = open_the_proc,   //open callback
    .release = single_release,
    .read = seq_read,        //read
    .write = write_msg,      //write callback
    .llseek = seq_lseek,
};

static int __init module_start(void){
    // create proc entry with read/write functionality
    struct proc_dir_entry *entry = proc_create(DEV_NAME, 0777, NULL, &new_fops);
    if(!entry) {
        return -1;
    }else {
        printk(KERN_INFO "Init Module [OK]\n");
    }
    return 0;
}

static void __exit module_stop(void){
    if (message){
        kfree(message);
    }
    // remove proc entry
    remove_proc_entry(DEV_NAME, NULL);
    printk(KERN_INFO "Exit Module [OK]\n");
}

module_init(module_start);
module_exit(module_stop);

#include <linux/fs.h>           // file operations
#include <linux/proc_fs.h>      // proc_create, proc_ops
#include <linux/uaccess.h>      // copy_from_user, copy_to_user
#include <linux/init.h>         // kernel initialization
#include <linux/seq_file.h>     // seq_read, seq_lseek, single_open, single_release
#include <linux/module.h>       // all modules need this
#include <linux/slab.h>         // memory allocation (kmalloc/kzalloc)
#include <linux/kernel.h>       // kernel logging
#include <linux/sched/signal.h> // For task_struct and process iteration
#include <linux/mm.h>

#define PROCFS_NAME "memory_info" // name of the proc entry

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Creates /proc entry with read/write functionality.");

static char *message = NULL;

// Proc dir entry
static struct proc_dir_entry *our_proc_file;

struct process_info
{
    char *name;                    // Process name
    int total_pids;                // Total number of PIDs in this group
    pid_t *pids;                   // Dynamic array of PID numbers
    unsigned long total_pages;     // Total number of pages
    unsigned long valid_pages;     // Number of valid pages
    unsigned long invalid_pages;   // Number of invalid pages
    unsigned long readonly_pages;  // Number of read-only pages
    unsigned long readonly_groups; // Number of groups of identical read-only pages
    struct process_info *next;     // Next node in the hash chain
};

#define HASH_SIZE 256
static struct process_info *process_hash_table[HASH_SIZE];

unsigned int hash(const char *str)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash % HASH_SIZE;
}

// this function reads a message from the pseudo file system via the seq_printf function
static int show_the_proc(struct seq_file *a, void *v)
{
    seq_printf(a, "%s\n", message);
    return 0;
}

// this function opens the proc entry by calling the show_the_proc function
static int open_the_proc(struct inode *inode, struct file *file)
{
    return single_open(file, show_the_proc, NULL);
}

static char command_buffer[1024]; // Buffer to store command input
static char output_buffer[4096];  // Buffer to store command output
static int output_size = 0;       // Size of the current output

// Function to add process information to the hash table
void add_process_info(struct task_struct *task)
{
    unsigned int hash_index = hash(task->comm);
    struct process_info *info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
    unsigned long valid_pages = 0;

    if (!info)
        return; // Handle kmalloc failure

    // Initialize the struct
    info->name = kstrdup(task->comm, GFP_KERNEL);
    info->pids = kmalloc(sizeof(pid_t), GFP_KERNEL);
    info->pids[0] = task->pid;
    info->total_pids = 1;
    info->total_pages = get_mm_rss(task->mm);
    if (task->mm)
    {
        if (task->mm)
        {
            valid_pages = atomic_long_read(&task->mm->rss_stat.count[MM_FILEPAGES]) +
                          atomic_long_read(&task->mm->rss_stat.count[MM_ANONPAGES]) +
                          atomic_long_read(&task->mm->rss_stat.count[MM_SHMEMPAGES]);
        }
        info->valid_pages = valid_pages;
    }
    info->valid_pages = valid_pages;                             // Example for valid pages
    info->invalid_pages = info->total_pages - info->valid_pages; // Simplified calculation
    info->readonly_pages = 0;                                    // count_readonly_pages(task);
    info->readonly_groups = 0;                                   // count_readonly_groups(task); // Placeholder for actual implementation
    info->next = NULL;

    // Insert into the hash table
    if (process_hash_table[hash_index] != NULL)
    {
        info->next = process_hash_table[hash_index]; // Handle collision
    }
    process_hash_table[hash_index] = info;
}

// Function to gather and populate process information
void gather_and_populate_data(void)
{
    struct task_struct *task;
    rcu_read_lock();
    for_each_process(task)
    {
        if (task->mm)
        { // Ensure the task has a memory descriptor
            add_process_info(task);
        }
    }
    rcu_read_unlock();
}

// Resets the data structure and re-populates it
void handle_reset(void)
{
    // clear_data_structure();
    gather_and_populate_data();
}

void append_process_info_to_output(struct process_info *info)
{
    char temp_buffer[512];
    int i;
    snprintf(temp_buffer, sizeof(temp_buffer), "%s, total: %lu, valid: %lu, invalid: %lu, may be shared: %lu, nb group: %lu, pid(%d): ",
             info->name, info->total_pages, info->valid_pages, info->invalid_pages,
             info->readonly_pages, info->readonly_groups, info->total_pids);

    strcat(output_buffer, temp_buffer);

    for (i = 0; i < info->total_pids; i++)
    {
        char pid_buffer[32];
        snprintf(pid_buffer, sizeof(pid_buffer), "%u; ", info->pids[i]);
        strcat(output_buffer, pid_buffer);
    }

    strcat(output_buffer, "\n");
    output_size = strlen(output_buffer);
}

void free_process_info(struct process_info *info)
{
    kfree(info->pids);
    kfree(info->name);
    kfree(info);
}

// Lists all processes and their memory info
void handle_all(void)
{
    struct process_info *info;
    int i;

    for (i = 0; i < HASH_SIZE; i++)
    {
        info = process_hash_table[i];
        while (info)
        {
            append_process_info_to_output(info);
            info = info->next;
        }
    }
}

// Filters process info by name
void handle_filter(const char *name)
{
    unsigned int hash_index = hash(name);
    struct process_info *info = process_hash_table[hash_index];

    while (info)
    {
        if (strcmp(info->name, name) == 0)
        {
            append_process_info_to_output(info);
            break;
        }
        info = info->next;
    }
}

// Deletes all process info for a given name
void handle_del(const char *name)
{
    unsigned int hash_index = hash(name);
    struct process_info *info = process_hash_table[hash_index], *prev = NULL;

    while (info)
    {
        if (strcmp(info->name, name) == 0)
        {
            if (prev)
            {
                prev->next = info->next;
            }
            else
            {
                process_hash_table[hash_index] = info->next;
            }
            free_process_info(info);
            snprintf(output_buffer, sizeof(output_buffer), "[SUCCESS]\n");
            output_size = strlen(output_buffer);
            return;
        }
        prev = info;
        info = info->next;
    }

    snprintf(output_buffer, sizeof(output_buffer), "[ERROR]: No such process\n");
    output_size = strlen(output_buffer);
}

void process_command(const char *command)
{
    output_size = 0; // Reset output size

    if (strncmp(command, "RESET", 5) == 0)
    {
        handle_reset();
        snprintf(output_buffer, sizeof(output_buffer), "[SUCCESS]\n");
        output_size = strlen(output_buffer);
    }
    else if (strncmp(command, "ALL", 3) == 0)
    {
        handle_all();
    }
    else if (strncmp(command, "FILTER|", 7) == 0)
    {
        handle_filter(command + 7); // Pass the name part of the command
    }
    else if (strncmp(command, "DEL|", 4) == 0)
    {
        handle_del(command + 4); // Pass the name part of the command
    }
    else
    {
        snprintf(output_buffer, sizeof(output_buffer), "[ERROR]: Unknown command\n");
        output_size = strlen(output_buffer);
    }
}

// Read operation for the /proc file
static ssize_t procfile_read(struct file *file, char __user *buffer, size_t size, loff_t *offset)
{
    int len = min(size, (size_t)output_size);
    if (*offset >= len)
        return 0; // EOF

    if (copy_to_user(buffer, output_buffer, len))
        return -EFAULT;

    *offset += len; // Update offset for the next read
    return len;
}

// Write operation for the /proc file
static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
    if (count > sizeof(command_buffer) - 1)
        return -EFAULT;

    if (copy_from_user(command_buffer, buffer, count))
        return -EFAULT;

    command_buffer[count] = '\0'; // Null terminate the string

    // Process the command
    process_command(command_buffer);

    return count;
}

/*-----------------------------------------------------------------------*/
// Structure that associates a set of function pointers (e.g., device_open)
// that implement the corresponding file operations (e.g., open).
/*-----------------------------------------------------------------------*/
static struct file_operations proc_file_operations = {
    // defined in linux/fs.h
    .owner = THIS_MODULE,
    .open = open_the_proc, // open callback
    .release = single_release,
    .read = procfile_read,   // read
    .write = procfile_write, // write callback
    .llseek = seq_lseek,
};

// Initialize module
static int __init memory_info_init(void)
{
    int i;
    for (i = 0; i < HASH_SIZE; i++)
    {
        process_hash_table[i] = NULL;
    }

    // Create proc entry
    our_proc_file = proc_create(PROCFS_NAME, 0666, NULL, &proc_file_operations);
    if (our_proc_file == NULL)
    {
        remove_proc_entry(PROCFS_NAME, NULL);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);

    // Populate initial data
    gather_and_populate_data();

    return 0;
}

// Cleanup module
static void __exit memory_info_exit(void)
{
    int i;
    struct process_info *info, *temp;

    // Free the hash table entries
    for (i = 0; i < HASH_SIZE; i++)
    {
        info = process_hash_table[i];
        while (info)
        {
            temp = info;
            info = info->next;
            kfree(temp->pids);
            kfree(temp->name);
            kfree(temp);
        }
    }

    // Remove proc entry
    remove_proc_entry(PROCFS_NAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
}

module_init(memory_info_init);
module_exit(memory_info_exit);


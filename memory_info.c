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
#include <linux/hashtable.h>
#include <linux/string.h>

#define PROCFS_NAME "memory_info" // name of the proc entry

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antoine Grosjean, Florent Hervers");
MODULE_DESCRIPTION("Creates /proc entry with read/write functionality.");

static char *message = NULL;

// Proc dir entry
static struct proc_dir_entry *our_proc_file;

#define HASH_TABLE_SIZE 16

static int err = 0;

/// @brief Structure that stores all values about a set of processes
/// with the same name.
struct process_info
{
    char *name;                    // Process name
    int total_pids;                // Total number of PIDs in this group
    pid_t pid;                     // PID number
    unsigned long total_pages;     // Total number of pages
    unsigned long valid_pages;     // Number of valid pages
    unsigned long invalid_pages;   // Number of invalid pages
    unsigned long readonly_pages;  // Number of read-only pages
    unsigned long readonly_groups; // Number of groups of identical read-only pages
    struct process_info *next;     // Next node in the hash chain
    struct hlist_node hnode;
};

/// @brief Add the values of the item2 fields to the item1 ones
/// @param item1 process_info stucture where values of fields will be gathered
/// @param item2 process_info structure that will be added
/// @return process info structure item1 with fields update according item2
struct process_info *gather_items(struct process_info *item1, struct process_info *item2)
{
    item1->total_pids += item2->total_pids;
    item1->total_pages += item2->total_pages;
    item1->valid_pages += item2->valid_pages;
    item1->invalid_pages += item2->invalid_pages;
    item1->readonly_pages += item2->readonly_pages;
    item1->readonly_groups += item2->readonly_groups;
    return item1;
}
////////////////
// Hash Table //
////////////////

/// @brief Define a hashtable of name [name] and size 2^[bits]
/// @param  name
/// @param  bits
DEFINE_HASHTABLE(process_hash_table, HASH_TABLE_SIZE);

/// @brief Add a new item to the hasht table
/// @param new_item process_info structure to add to the hash table
void add_to_hash_table(struct process_info *new_item)
{
    unsigned long hash = full_name_hash(NULL, new_item->name, strlen(new_item->name));
    struct process_info *existing_item;
    // Check if the key already exists and handle according to policy
    hash_for_each_possible(process_hash_table, existing_item, hnode, hash)
    {
        if (strcmp(existing_item->name, new_item->name) == 0)
        {
            while (existing_item->next != NULL)
            {
                existing_item = gather_items(existing_item, new_item);
                existing_item = existing_item->next;
            }
            existing_item = gather_items(existing_item, new_item);
            existing_item->next = new_item;
            return;
        }
    }
    hash_add(process_hash_table, &new_item->hnode, hash);
}

/// @brief Look for items which name is [name]
/// @param name string
/// @return Items matching the name
struct process_info *find_in_hash_table(char *name)
{
    struct process_info *item;
    size_t name_len;
    unsigned long hash;

    if (!name)
        return NULL; // Check for NULL pointer

    name_len = strlen(name);
    hash = full_name_hash(NULL, name, name_len);

    hash_for_each_possible(process_hash_table, item, hnode, hash)
    {
        if (strcmp(item->name, name) == 0)
        {
            return item; // Successful match
        }
    }
    return NULL; // No match found
}

/// @brief Remove an item from hash table
/// @param item process_info structure to be removed
void remove_from_hash_table(struct process_info *item)
{
    hash_del(&item->hnode);
}
////////////////////////////////////////////////////////////////

// Buffer storing the output
static char *output_buffer = NULL;
// Size of the output buffer (can be resized if needed)
static size_t output_buffer_size = 0;
// Current position for reading in the output buffer
static size_t output_buffer_pos = 0;

/// @brief Reset and clear the output buffer
void reset_output_buffer(void)
{
    output_buffer_size = 0;
    output_buffer_pos = 0;
}

/// @brief Free memory allocated to save process information
/// @param info process_info structure to be freed
void free_process_info(struct process_info *info)
{
    kfree(info->name);
}

/// @brief Append data to the output buffer
/// @param data data to append
/// @param data_size size of the data
static int append_to_output_buffer(const char *data, size_t data_size)
{
    char *new_buffer;

    if (output_buffer_pos + data_size >= output_buffer_size)
    {
        size_t new_size = (output_buffer_size == 0) ? 1024 : output_buffer_size * 2;
        while (output_buffer_pos + data_size >= new_size)
        {
            new_size *= 2;
        }
        new_buffer = krealloc(output_buffer, new_size, GFP_KERNEL);
        if (!new_buffer)
        {
            err = -ENOMEM;
            printk(KERN_ERR "[ERROR] Memory allocation error\n");
            reset_output_buffer();
            append_to_output_buffer("[ERROR] Memory allocation error\n", strlen("[ERROR] Memory allocation error\n"));
            return -1;
        }
        output_buffer = new_buffer;
        output_buffer_size = new_size;
    }

    memcpy(output_buffer + output_buffer_pos, data, data_size);
    output_buffer_pos += data_size;
    return 0;
}

int print_file(char *error_message)
{
    reset_output_buffer();
    if (append_to_output_buffer(error_message, strlen(error_message)))
        return -1;

    return 0;
}

/// @brief Save the memory information of a process
/// @param task Task we want to save the memory information
int save_process_info(struct task_struct *task)
{
    struct process_info *info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
    unsigned long valid_pages = 0;

    if (!info)
    {
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_file("[ERROR] Memory allocation error\n");
        return -1;
    }
    // Initialize the struct
    info->name = kstrdup(task->comm, GFP_KERNEL);
    if (!info->name)
    {
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_file("[ERROR] Memory allocation error\n");
        return -1;
    }
    info->pid = task->pid;
    info->total_pids = 1;
    info->total_pages = get_mm_rss(task->mm);
    if (task->mm)
    {
        valid_pages = atomic_long_read(&task->mm->rss_stat.count[MM_FILEPAGES]) +
                      atomic_long_read(&task->mm->rss_stat.count[MM_ANONPAGES]) +
                      atomic_long_read(&task->mm->rss_stat.count[MM_SHMEMPAGES]);
    }

    info->valid_pages = valid_pages;                             // Example for valid pages
    info->invalid_pages = info->total_pages - info->valid_pages; // Simplified calculation
    info->readonly_pages = 0;                                    // TODO count_readonly_pages(task);
    info->readonly_groups = 0;                                   // TODO count_readonly_groups(task); // Placeholder for actual implementation
    info->next = NULL;

    // Insert into the hash table
    add_to_hash_table(info);
    return 0;
}

/// @brief Gather and populate process information
int gather_and_populate_data(void)
{
    struct task_struct *task;
    rcu_read_lock();
    for_each_process(task)
    {
        if (task->mm)
        { // Ensure the task has a memory descriptor
            if (save_process_info(task))
                return -1;
        }
    }
    rcu_read_unlock();
    return 0;
}

/// @brief Clear the hash table and free all allocated memory
void clear_data_structure(void)
{
    struct process_info *info, *tmp, *del;
    unsigned int bkt;

    hash_for_each(process_hash_table, bkt, info, hnode)
    {
        tmp = info->next;
        while (tmp != NULL)
        {
            del = tmp;
            tmp = tmp->next;
            free_process_info(del);
            kfree(del);
        }
        remove_from_hash_table(info);
        kfree(info);
    }
}

/// @brief Append memory information to the output buffer
/// @param info process_info structure to be appened to the buffer
int append_process_info_to_output(struct process_info *info)
{
    char info_buffer[512];
    struct process_info *tmp;

    int len = snprintf(info_buffer, sizeof(info_buffer), "%s, total: %lu, valid: %lu, invalid: %lu, may be shared: %lu, nb group: %lu, pid(%d):",
                       info->name, info->total_pages, info->valid_pages, info->invalid_pages,
                       info->readonly_pages, info->readonly_groups, info->total_pids);
    if (append_to_output_buffer(info_buffer, len))
        return -1;

    tmp = info;
    while (tmp != NULL)
    {
        char pid_buffer[32];
        int pid_len = snprintf(pid_buffer, sizeof(pid_buffer), " %u", tmp->pid);
        if (append_to_output_buffer(pid_buffer, pid_len))
            return -1;

        tmp = tmp->next;
        if (!tmp)
        {
            if (append_to_output_buffer("\n", strlen("\n")))
                return -1;
        }
        else
        {
            if (append_to_output_buffer(";", strlen("\n")))
                return -1;
        }
    }
    return 0;
}

//////////////
// Commands //
//////////////

/// @brief Reset the data structure and re-populates it
int handle_reset(void)
{
    clear_data_structure();
    if (gather_and_populate_data())
        return -1;
    if (print_file("[SUCCESS]\n"))
        return -1;
    return 0;
}

/// @brief Lists all processes and their memory info
int handle_all(void)
{
    struct process_info *info;
    unsigned int bkt;

    hash_for_each(process_hash_table, bkt, info, hnode)
    {
        if (append_process_info_to_output(info))
            return -1;
    }
    return 0;
}

/// @brief Filters process_info by name
/// @param name name used to filter process_info
int handle_filter(char *name)
{
    struct process_info *info = find_in_hash_table(name);
    if (!info)
    {
        err = -ESRCH;
        printk(KERN_ERR "[ERROR]: No such process\n");
        if (print_file("[ERROR]: No such process\n"))
            return -1;
        return -1;
    }
    if (append_process_info_to_output(info))
        return -1;
    return 0;
}

/// @brief Deletes all process_info for a given name
/// @param name name of the process_info to be deleted
int handle_del(char *name) // TODO verify if it works
{
    struct process_info *info = find_in_hash_table(name), *tmp, *del;
    if (info != NULL)
    {
        tmp = info->next;
        while (tmp != NULL)
        {
            del = tmp;
            tmp = tmp->next;
            free_process_info(del);
            kfree(del);
        }
        remove_from_hash_table(info);
        kfree(info);

        if (print_file("[SUCCESS]\n"))
            return -1;
    }
    else
    {
        err = -ESRCH;
        printk(KERN_ERR "[ERROR]: No such process\n");
        if (print_file("[ERROR]: No such process\n"))
            return -1;
    }
    return 0;
}

/// @brief Parse the command given by user
/// @param command string containing the given command
int process_command(char *command)
{
    reset_output_buffer();

    if (strncmp(command, "RESET", strlen(command)) == 0)
    {
        if (handle_reset())
            return -1;
        if (print_file("[SUCCESS]\n"))
            return -1;
    }
    else if (strncmp(command, "ALL", strlen(command)) == 0)
    {
        if (handle_all())
            return -1;
    }
    else if (strncmp(command, "FILTER|", 7) == 0)
    {
        if (handle_filter(command + 7)) // Pass the name part of the command
            return -1;
    }
    else if (strncmp(command, "DEL|", 4) == 0)
    {
        if (handle_del(command + 4)) // Pass the name part of the command
            return -1;
    }
    else
    {
        err = -EINVAL;
        printk(KERN_ERR "[ERROR]: Invalid argument\n");
        if (print_file("[ERROR]: Invalid argument\n"))
            return -1;
    }
    return 0;
}

//////////////////////////////////////////////////////////////

/// @brief Read operation for the /proc file
static ssize_t procfile_read(struct file *file, char __user *buffer, size_t count, loff_t *offset)
{
    size_t available;
    size_t to_copy;

    if (*offset >= output_buffer_pos)
        return 0; // End of file

    available = output_buffer_pos - *offset;
    to_copy = min(available, count);
    if (copy_to_user(buffer, output_buffer + *offset, to_copy))
    {
        kfree(output_buffer);
        err = -EFAULT;
        printk(KERN_ERR "[ERROR] Bad address\n");
        print_file("[ERROR] Bad address\n");
        return err;
    }

    *offset += to_copy;
    return to_copy;
}

/// @brief Write operation for the /proc file
static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) // TODO return message and not error
{
    char *command_buffer = kzalloc(count + 1, GFP_KERNEL);
    if (!command_buffer)
    {
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_file("[ERROR] Memory allocation error\n");
        return -ENOMEM;
    }

    // copy data from user space to kernel space by using copy_from_user
    if (copy_from_user(command_buffer, buffer, count))
    {
        kfree(command_buffer);
        err = -EFAULT;
        printk(KERN_ERR "[ERROR] Bad address\n");
        print_file("[ERROR] Bad address\n");
        return err;
    }
    if (command_buffer[count - 1] == '\n')
    {
        command_buffer[count - 1] = '\0';
    }

    // Process the command
    if (process_command(command_buffer))
        return err;

    return count;
}

/*-----------------------------------------------------------------------*/
// Structure that associates a set of function pointers (e.g., device_open)
// that implement the corresponding file operations (e.g., open).
/*-----------------------------------------------------------------------*/
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
static struct file_operations proc_file_operations = {
    // defined in linux/fs.h
    .owner = THIS_MODULE,
    .open = open_the_proc, // open callback
    .release = single_release,
    .read = procfile_read,   // read
    .write = procfile_write, // write callback
    .llseek = seq_lseek,
};

/// @brief Initialize module
static int __init memory_info_init(void)
{
    hash_init(process_hash_table);

    // Create proc entry
    our_proc_file = proc_create(PROCFS_NAME, 0666, NULL, &proc_file_operations);
    if (our_proc_file == NULL)
    {
        remove_proc_entry(PROCFS_NAME, NULL);
        err = -ENOENT;
        printk(KERN_ALERT "[ERROR] No such file or directory\n");
        print_file("[ERROR] No such file or directory\n");
        return err;
    }

    printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);

    // Populate initial data
    gather_and_populate_data();

    return err;
}

/// @brief Cleanup module
static void __exit memory_info_exit(void)
{
    clear_data_structure();

    // Remove proc entry
    remove_proc_entry(PROCFS_NAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
}

module_init(memory_info_init);
module_exit(memory_info_exit);
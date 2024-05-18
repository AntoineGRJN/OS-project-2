#include <linux/fs.h>           // file operations
#include <linux/proc_fs.h>      // proc_create, proc_ops
#include <linux/uaccess.h>      // copy_from_user, copy_to_user
#include <linux/init.h>         // kernel initialization
#include <linux/seq_file.h>     // seq_read, seq_lseek, single_open, single_release
#include <linux/module.h>       // all modules need this
#include <linux/slab.h>         // memory allocation (kmalloc/kzalloc)
#include <linux/kernel.h>       // kernel logging
#include <linux/sched/signal.h> // For task_struct and process iteration
#include <linux/mm.h>           // memory information
#include <linux/mm_types.h>     // memory information
#include <linux/hashtable.h>    // hastable
#include <linux/list.h>         // list
#include <linux/string.h>       // string (strlen)
#include <asm/highmem.h>        //
#include <linux/crypto.h>       // SHA256 hash
#include <crypto/hash.h>        // SHA256 hash

#define PROCFS_NAME "memory_info" // name of the proc entry
#define HASH_TABLE_SIZE 16
#define FIXED_PAGE_SIZE 4096
#define SHA256_DIGEST_LENGTH 8

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antoine Grosjean, Florent Hervers");
MODULE_DESCRIPTION("Creates /proc entry with read/write functionality.");

/// @brief Define a hashtable of name [name] and size 2^[bits]
/// @param  name
/// @param  bits
static DEFINE_HASHTABLE(process_hash_table, HASH_TABLE_SIZE);

/// @brief List of hashed readable and valid pages
static LIST_HEAD(hashed_readable_pages);
/// @brief List of readable and valid pages
static LIST_HEAD(readable_pages);
static DEFINE_SPINLOCK(readable_pages_lock);        // Lock for readable_pages list
static DEFINE_SPINLOCK(hashed_readable_pages_lock); // Lock for hashed_readable_pages list

/*
    Global variables
*/

// Proc dir entry
static struct proc_dir_entry *our_proc_file;
// Global variable to return error code
static int err = 0;
// Buffer storing the output
static char *output_buffer = NULL;
// Size of the output buffer (can be resized if needed)
static size_t output_buffer_size = 0;
// Current position for reading in the output buffer
static size_t output_buffer_pos = 0;

/*
    Definitions of structures
*/

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
    unsigned long readable_pages;  // Number of readable pages
    unsigned long readable_groups; // Number of groups of identical readable pages
    struct process_info *next;     // Next node in the hash chain
    struct hlist_node hnode;       // struct for hash table
};
/// @brief Structure that stores a readable page
struct page_ref
{
    struct list_head list;
    struct page *page;
};
/// @brief Structure that stores a hash of a readable page and a counter
/// of the amount of identical page
struct hash_entry
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int count; // Number of identical pages
    struct list_head list;
};

/*
    Declarations of the functions
*/

// Utility functions

struct process_info *gather_items(struct process_info *item1, struct process_info *item2);
void reset_output_buffer(void);
void clear_data_structure(void);
int print_error_message(char *error_message);
void free_process_info(struct process_info *info);

// Hash table functions

void add_to_hash_table(struct process_info *new_item);
struct process_info *find_in_hash_table(char *name);
void remove_from_hash_table(struct process_info *item);

// Set values functions

struct hash_entry *add_hashed_readable_page(unsigned char *hash);
int count_identical_pages(struct process_info *initial_process);
int set_valid_pages(struct process_info *initial_process);
int save_process_info(struct task_struct *task);

// Output buffer functions

int append_to_output_buffer(const char *data, size_t data_size);
int append_process_info_to_output(struct process_info *info);

// Populate functions

int gather_and_populate_data(void);

// Commands handeling

int handle_reset(void);
int handle_all(void);
int handle_filter(char *name);
int handle_del(char *name);
int process_command(char *command);

// Read and write in memory_info function and structure

ssize_t procfile_read(struct file *file, char __user *buffer, size_t count, loff_t *offset);
ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset);
struct file_operations proc_file_operations = {
    // defined in linux/fs.h
    .owner = THIS_MODULE,
    .read = procfile_read,   // read
    .write = procfile_write, // write
};

// Initialise and unload module_project_os

int __init memory_info_init(void);
void __exit memory_info_exit(void);

/*
    Definitions of functions
*/

/*=========
   Utility
  =========*/

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
    item1->readable_pages += item2->readable_pages;
    item1->readable_groups += item2->readable_groups;
    return item1;
}

/// @brief Reset and clear the output buffer
void reset_output_buffer(void)
{
    output_buffer_size = 0;
    output_buffer_pos = 0;
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

/// @brief Put [error_message] into the output buffer
/// @param error_message string to put into output buffer
int print_error_message(char *error_message)
{
    reset_output_buffer();
    if (append_to_output_buffer(error_message, strlen(error_message)))
        return -1;

    return 0;
}

/// @brief Free memory allocated to save process information
/// @param info process_info structure to be freed
void free_process_info(struct process_info *info)
{
    kfree(info->name);
}

/*============
   Hash Table
  ============*/

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
            // Append to the end of chained list
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

/*============
   Set values
  ============*/

struct hash_entry *add_hashed_readable_page(unsigned char *hash)
{
    struct hash_entry *entry;
    // Check for extisting entry
    list_for_each_entry(entry, &hashed_readable_pages, list)
    {
        if (memcmp(entry->hash, hash, SHA256_DIGEST_LENGTH) == 0)
        {
            return entry;
        }
    }
    entry = kmalloc(sizeof(struct hash_entry), GFP_KERNEL);
    if (!entry)
    {
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_error_message("[ERROR] Memory allocation error\n");
        return NULL;
    }

    memcpy(entry->hash, hash, SHA256_DIGEST_LENGTH);
    entry->count = 0;

    // Add to the list
    INIT_LIST_HEAD(&entry->list);
    list_add(&entry->list, &hashed_readable_pages);
    return entry;
}

int count_identical_pages(struct process_info *initial_process)
{
    int may_be_shared = 0;
    int group_count = 0;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    struct page_ref *page;
    struct hash_entry *entry;
    struct hash_entry *to_del;
    struct hash_entry *s;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_error_message("[ERROR] Memory allocation error\n");
        return -1;
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        crypto_free_shash(tfm);
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_error_message("[ERROR] Memory allocation error\n");
        return -1;
    }
    desc->tfm = tfm;

    spin_lock(&readable_pages_lock);
    list_for_each_entry(page, &readable_pages, list)
    {
        unsigned char *kaddr;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        struct hash_entry *new_entry;

        if (!page || !page->page)
        {
            kfree(desc);
            crypto_free_shash(tfm);
            printk(KERN_ERR "[ERROR] Invalid page entry\n");
            print_error_message("[ERROR] Invalid page entry\n");
            return -1;
        }
        kaddr = kmap(page->page);
        if (!kaddr)
        {
            kfree(desc);
            crypto_free_shash(tfm);
            printk(KERN_ERR "[ERROR] Failed to map page\n");
            print_error_message("[ERROR] Failed to map page\n");
            return -1;
        }

        // Hash the page and create the hash to add to the list
        crypto_shash_init(desc);
        crypto_shash_update(desc, kaddr, FIXED_PAGE_SIZE);
        crypto_shash_final(desc, hash);
        kunmap(page->page);

        new_entry = add_hashed_readable_page(hash);
        if (!new_entry)
        {
            spin_unlock(&readable_pages_lock);
            kfree(desc);
            crypto_free_shash(tfm);
            spin_lock(&hashed_readable_pages_lock);
            list_for_each_entry_safe(to_del, s, &hashed_readable_pages, list)
            {
                list_del(&to_del->list);
                kfree(to_del);
            }
            spin_unlock(&hashed_readable_pages_lock);
            return -1;
        }
        new_entry->count++;
    }
    spin_unlock(&readable_pages_lock);

    // Count the number of groups of identical pages
    spin_lock(&hashed_readable_pages_lock);
    list_for_each_entry(entry, &hashed_readable_pages, list)
    {
        if (entry->count > 1)
        {
            may_be_shared += entry->count;
            group_count++;
        }
    }
    spin_unlock(&hashed_readable_pages_lock);

    // Set values in the process_info
    initial_process->readable_pages = may_be_shared;
    initial_process->readable_groups = group_count;

    kfree(desc);
    crypto_free_shash(tfm);

    // Free the hash list
    spin_lock(&hashed_readable_pages_lock);
    list_for_each_entry_safe(to_del, s, &hashed_readable_pages, list)
    {
        list_del(&to_del->list);
        kfree(to_del);
    }
    spin_unlock(&hashed_readable_pages_lock);

    return 0;
}

///@brief given the intial_process, find if there are identical readable
/// pages and append the value to the given struct
///@param initial_process process_info struct where values for pages will be set
int set_valid_pages(struct process_info *initial_process)
{
    struct mm_struct *mm;
    struct pid *pid_struct;
    struct vm_area_struct *vma;
    unsigned long address;
    struct process_info *process;
    struct page_ref *to_del;
    struct page_ref *s;
    int valid_pages = 0;

    process = initial_process;
    // Iterate on every task
    while (process != NULL)
    {
        pid_struct = find_get_pid(process->pid);
        mm = pid_task(pid_struct, PIDTYPE_PID)->mm;
        if (!mm)
        {
            printk(KERN_ERR "[ERROR] No memory management structure for the process.\n");
            print_error_message("[ERROR] No memory management structure for the process.\n");
            return -1;
        }

        // Lock the memory map semaphore
        down_read(&mm->mmap_sem);
        for (vma = mm->mmap; vma; vma = vma->vm_next)
        {
            // Walk into the pages tables to find the pages
            for (address = vma->vm_start; address < vma->vm_end; address += FIXED_PAGE_SIZE)
            {
                pgd_t *pgd;
                p4d_t *p4d;
                pud_t *pud;
                pmd_t *pmd;
                pte_t *pte;
                // Get the page table entry for the current address
                pgd = pgd_offset(mm, address);
                if (pgd_none(*pgd) || pgd_bad(*pgd))
                    continue;
                p4d = p4d_offset(pgd, address);
                if (p4d_none(*p4d) || p4d_bad(*p4d))
                    continue;
                pud = pud_offset(p4d, address);
                if (pud_none(*pud) || pud_bad(*pud))
                    continue;
                pmd = pmd_offset(pud, address);
                if (pmd_none(*pmd) || pmd_bad(*pmd) || !pmd_present(*pmd))
                    continue;
                pte = pte_offset_map(pmd, address);
                if (!pte || pte_none(*pte))
                    continue;

                // Append the page to the list if we found it
                if (pte_present(*pte))
                {
                    valid_pages += 1;
                    // append the pages only if they have the read authorization
                    if (vma->vm_flags & VM_READ)
                    {
                        struct page_ref *elem = kmalloc(sizeof(struct page_ref), GFP_KERNEL);
                        if (!elem)
                        {
                            pte_unmap(pte);
                            up_read(&mm->mmap_sem);
                            spin_lock(&readable_pages_lock);
                            list_for_each_entry_safe(to_del, s, &readable_pages, list)
                            {
                                list_del(&to_del->list);
                                kfree(to_del);
                            }
                            spin_unlock(&readable_pages_lock);
                            err = -ENOMEM;
                            printk(KERN_ERR "[ERROR] Memory allocation error\n");
                            print_error_message("[ERROR] Memory allocation error\n");
                            return -1;
                        }
                        elem->page = pte_page(*pte);
                        if (elem->page && !PageReserved(elem->page))
                        {
                            spin_lock(&readable_pages_lock);
                            INIT_LIST_HEAD(&elem->list);
                            list_add_tail(&elem->list, &readable_pages);
                            spin_unlock(&readable_pages_lock);
                        }
                    }
                }
                pte_unmap(pte);
            }
        }
        up_read(&mm->mmap_sem); // Release the memory map semaphore
        process = process->next;
    }

    // Update the statistics contained in the structure
    process = initial_process;
    while (process != NULL)
    {
        process->valid_pages = valid_pages;
        process->invalid_pages = process->total_pages - process->valid_pages;
        process = process->next;
    }

    // Count the number of identical pages and group of identical pages
    if (count_identical_pages(initial_process))
    {
        spin_lock(&readable_pages_lock);
        list_for_each_entry_safe(to_del, s, &readable_pages, list)
        {
            list_del(&to_del->list);
            kfree(to_del);
        }
        spin_unlock(&readable_pages_lock);
        return -1;
    }

    // Free the list
    spin_lock(&readable_pages_lock);
    list_for_each_entry_safe(to_del, s, &readable_pages, list)
    {
        list_del(&to_del->list);
        kfree(to_del);
    }
    spin_unlock(&readable_pages_lock);

    return 0;
}

/// @brief Save the memory information of a process
/// @param task Task we want to save the memory information
int save_process_info(struct task_struct *task)
{
    struct process_info *info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
    if (!info)
    {
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_error_message("[ERROR] Memory allocation error\n");
        return -1;
    }
    // Initialize the struct
    info->name = kstrdup(task->comm, GFP_KERNEL);
    if (!info->name)
    {
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_error_message("[ERROR] Memory allocation error\n");
        return -1;
    }
    info->pid = task->pid;
    info->total_pids = 1;
    if (task->mm)

    {
        info->total_pages = task->mm->total_vm;
    }

    info->valid_pages = 0;
    info->invalid_pages = 0;
    info->readable_pages = 0;
    info->readable_groups = 0;
    info->next = NULL;

    // Insert into the hash table
    add_to_hash_table(info);

    return 0;
}

/*==============
  Output Buffer
 ===============*/

/// @brief Append data to the output buffer
/// @param data data to append
/// @param data_size size of the data
int append_to_output_buffer(const char *data, size_t data_size)
{
    char *new_buffer;

    // Check if the output buffer is large enough to append data
    if (output_buffer_pos + data_size >= output_buffer_size)
    {
        // Multiply size of buffer by two untill there is enough space for data
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
            print_error_message("[ERROR] Memory allocation error\n");
            return -1;
        }
        output_buffer = new_buffer;
        output_buffer_size = new_size;
    }

    memcpy(output_buffer + output_buffer_pos, data, data_size);
    output_buffer_pos += data_size;
    return 0;
}

/// @brief Append memory information to the output buffer
/// @param info process_info structure to be appended to the buffer
int append_process_info_to_output(struct process_info *info)
{
    struct process_info *tmp;
    int len;
    char *info_buffer;
    char *pid_buffer;

    // Calculate the length of the info_buffer
    len = snprintf(NULL, 0, "%s, total: %lu, valid: %lu, invalid: %lu, may_be_shared: %lu, nb_group: %lu, pid(%d):",
                   info->name, info->total_pages, info->valid_pages, info->invalid_pages,
                   info->readable_pages, info->readable_groups, info->total_pids);

    info_buffer = kmalloc(len + 1, GFP_KERNEL);
    if (!info_buffer)
    {
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_error_message("[ERROR] Memory allocation error\n");
        return -1;
    }

    // Write the formatted string into the allocated buffer
    snprintf(info_buffer, len + 1, "%s, total: %lu, valid: %lu, invalid: %lu, may_be_shared: %lu, nb_group: %lu, pid(%d):",
             info->name, info->total_pages, info->valid_pages, info->invalid_pages,
             info->readable_pages, info->readable_groups, info->total_pids);

    if (append_to_output_buffer(info_buffer, len))
    {
        kfree(info_buffer);
        return -1;
    }
    kfree(info_buffer);

    tmp = info;
    while (tmp != NULL)
    {
        // Calculate the length of the pid_buffer
        len = snprintf(NULL, 0, " %u", tmp->pid);

        pid_buffer = kmalloc(len + 1, GFP_KERNEL);
        if (!pid_buffer)
        {
            err = -ENOMEM;
            printk(KERN_ERR "[ERROR] Memory allocation error\n");
            print_error_message("[ERROR] Memory allocation error\n");
            return -1;
        }

        // Write the formatted string into the allocated buffer
        snprintf(pid_buffer, len + 1, " %u", tmp->pid);

        if (append_to_output_buffer(pid_buffer, len))
        {
            kfree(pid_buffer);
            return -1;
        }
        kfree(pid_buffer);

        tmp = tmp->next;
        // Add end char= /n or ;
        if (!tmp)
        {
            if (append_to_output_buffer("\n", strlen("\n")))
                return -1;
        }
        else
        {
            if (append_to_output_buffer(";", strlen(";")))
                return -1;
        }
    }
    return 0;
}

/*==========
  Populate
 ==========*/

/// @brief Gather and populate process information
int gather_and_populate_data(void)
{
    struct task_struct *task;
    struct process_info *info;
    unsigned int bkt;

    rcu_read_lock();
    for_each_process(task)
    {
        if (task->mm)
        { // Ensure the task has a memory descriptor
            if (save_process_info(task))
            {
                clear_data_structure();
                rcu_read_unlock();
                return -1;
            }
        }
    }
    rcu_read_unlock();

    hash_for_each(process_hash_table, bkt, info, hnode)
    {
        if (set_valid_pages(info))
        {
            clear_data_structure();
            return -1;
        }
    }

    return 0;
}

/*==========
   Commands
 ===========*/

/// @brief Reset the data structure and re-populates it
int handle_reset(void)
{
    clear_data_structure();
    if (gather_and_populate_data())
        return -1;
    if (print_error_message("[SUCCESS]\n"))
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
        if (print_error_message("[ERROR]: No such process\n"))
            return -1;
        return -1;
    }
    if (append_process_info_to_output(info))
        return -1;
    return 0;
}

/// @brief Deletes all process_info for a given name
/// @param name name of the process_info to be deleted
int handle_del(char *name)
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

        if (print_error_message("[SUCCESS]\n"))
            return -1;
    }
    else
    {
        err = -ESRCH;
        printk(KERN_ERR "[ERROR]: No such process\n");
        if (print_error_message("[ERROR]: No such process\n"))
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
        if (print_error_message("[SUCCESS]\n"))
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
        if (print_error_message("[ERROR]: Invalid argument\n"))
            return -1;
    }
    return 0;
}

/*================
   Read and Write
 =================*/

/// @brief Read operation for the /proc file
ssize_t procfile_read(struct file *file, char __user *buffer, size_t count, loff_t *offset)
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
        print_error_message("[ERROR] Bad address\n");
        return err;
    }

    *offset += to_copy;
    return to_copy;
}

/// @brief Write operation for the /proc file
ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
    char *command_buffer = kzalloc(count + 1, GFP_KERNEL);
    if (!command_buffer)
    {
        err = -ENOMEM;
        printk(KERN_ERR "[ERROR] Memory allocation error\n");
        print_error_message("[ERROR] Memory allocation error\n");
        return count;
    }

    // copy data from user space to kernel space by using copy_from_user
    if (copy_from_user(command_buffer, buffer, count))
    {
        kfree(command_buffer);
        err = -EFAULT;
        printk(KERN_ERR "[ERROR] Bad address\n");
        print_error_message("[ERROR] Bad address\n");
        return count;
    }
    if (command_buffer[count - 1] == '\n')
    {
        command_buffer[count - 1] = '\0';
    }

    // Process the command
    if (process_command(command_buffer))
        return count;

    return count;
}

/*=================
   Init and unload
 ==================*/

/// @brief Initialize module
int __init memory_info_init(void)
{
    int err = 0;

    hash_init(process_hash_table);

    // Create proc entry
    our_proc_file = proc_create(PROCFS_NAME, 0666, NULL, &proc_file_operations);
    if (!our_proc_file)
    {
        printk(KERN_ALERT "[ERROR] Could not create /proc/%s\n", PROCFS_NAME);
        return -ENOENT;
    }
    printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);

    // Populate initial data
    if (gather_and_populate_data())
    {
        proc_remove(our_proc_file);
        return err;
    }

    return err;
}

/// @brief Cleanup module
void __exit memory_info_exit(void)
{
    clear_data_structure();
    // Remove proc entry
    remove_proc_entry(PROCFS_NAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
}

module_init(memory_info_init);
module_exit(memory_info_exit);
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
#include <linux/mm_types.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/string.h>
#include <asm/highmem.h>
#include <linux/crypto.h>
#include <crypto/hash.h>

#define PROCFS_NAME "memory_info" // name of the proc entry

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antoine Grosjean, Florent Hervers");
MODULE_DESCRIPTION("Creates /proc entry with read/write functionality.");

static char *message = NULL;

// Proc dir entry
static struct proc_dir_entry *our_proc_file;

#define HASH_TABLE_SIZE 16
#define FIXED_PAGE_SIZE 4096
#define SHA256_DIGEST_LENGTH 8

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

struct page_ref
{
    struct list_head list;
    struct page *page;
};

struct hash_entry
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int count; // Number of identical pages
    struct list_head list;
};

LIST_HEAD(hashed_readable_pages_list);
LIST_HEAD(readable_pages);

static DEFINE_SPINLOCK(readable_pages_lock);
static DEFINE_SPINLOCK(hashed_readable_pages_lock);

// If we decide to compare pages instead of hash
/*int compare_pages(struct page *page1, struct page *page2) {
    void *kaddr1, *kaddr2;
    int result;

    // Map the pages into kernel address space
    kaddr1 = kmap(page1);
    kaddr2 = kmap(page2);

    // Compare the contents
    result = memcmp(kaddr1, kaddr2, PAGE_SIZE);

    // Unmap the pages
    kunmap(page1);
    kunmap(page2);

    return result;
}*/

struct hash_entry *add_hashed_readable_page(unsigned char *hash)
{
    struct hash_entry *entry;
    list_for_each_entry(entry, &hashed_readable_pages_list, list)
    {
        if (memcmp(entry->hash, hash, SHA256_DIGEST_LENGTH) == 0)
        {
            return entry;
        }
    }
    entry = kmalloc(sizeof(struct hash_entry), GFP_KERNEL); // TODO allocation error
    if (!entry)
        return NULL;
    memcpy(entry->hash, hash, SHA256_DIGEST_LENGTH);
    entry->count = 0;
    INIT_LIST_HEAD(&entry->list);
    list_add(&entry->list, &hashed_readable_pages_list);
    return entry;
}

/*int count_readable_groups(struct process_info *initial_process)
{
    int may_be_shared = 0;
    int group_count = 0;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    struct page_ref *page;
    int i = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        pr_err("Failed to allocate shash\n");
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL); // TODO allocation error
    if (!desc)
    {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    spin_lock(&readable_pages_lock);
    list_for_each_entry(page, &readable_pages, list)
    {
        unsigned char *kaddr;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        printk(KERN_INFO "in: %d", i);
        kaddr = kmap(page->page);
        crypto_shash_init(desc);
        crypto_shash_update(desc, kaddr, FIXED_PAGE_SIZE);
        crypto_shash_final(desc, hash);
        kunmap(page->page);
        printk(KERN_INFO "out: %d", i);
        struct hash_entry *entry = add_hashed_readable_page(hash);
        if (entry)
        {
            entry->count++;
        }
        i++;
    }
    spin_unlock(&readable_pages_lock);

    printk(KERN_INFO "finish");

    // Count the number of groups of identical pages
    spin_lock(&hashed_readable_pages_lock);
    struct hash_entry *entry;
    list_for_each_entry(entry, &hashed_readable_pages_list, list)
    {
        if (entry->count > 1)
        {
            may_be_shared += entry->count;
            group_count++;
        }
        else
        {
            printk(KERN_INFO "loop: %d", entry->count);
        }
    }
    spin_unlock(&hashed_readable_pages_lock);

    initial_process->readonly_pages = may_be_shared;
    initial_process->readonly_groups = group_count;
    printk(KERN_INFO "may be shared: %d", may_be_shared);
    printk(KERN_INFO "groups: %d", group_count);

    kfree(desc);
    crypto_free_shash(tfm);

    printk(KERN_INFO "start free");
    // Free the hash list
    spin_lock(&hashed_readable_pages_lock);
    struct hash_entry *e;
    struct hash_entry *s;
    list_for_each_entry_safe(e, s, &hashed_readable_pages_list, list)
    {
        list_del(&e->list);
        kfree(e);
    }
    spin_unlock(&hashed_readable_pages_lock);

    if (list_empty(&hashed_readable_pages_list))
    {
        printk(KERN_INFO "freed");
    }
    printk(KERN_INFO "return");
    return 0;
}
*/

static int count_readable_groups(struct process_info *initial_process)
{
    int may_be_shared = 0;
    int group_count = 0;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    struct page_ref *page;
    int i = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        pr_err("Failed to allocate shash\n");
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    spin_lock(&readable_pages_lock);
    list_for_each_entry(page, &readable_pages, list)
    {
        unsigned char *kaddr;
        unsigned char hash[SHA256_DIGEST_LENGTH];

        if (!page || !page->page) {
            pr_err("Invalid page entry\n");
            continue;
        }

        printk(KERN_INFO "Processing page: %d", i);
        kaddr = kmap(page->page);
        if (!kaddr) {
            pr_err("Failed to map page\n");
            continue;
        }

        crypto_shash_init(desc);
        crypto_shash_update(desc, kaddr, FIXED_PAGE_SIZE);
        crypto_shash_final(desc, hash);
        kunmap(page->page);
        printk(KERN_INFO "Completed page: %d", i);

        struct hash_entry *entry = add_hashed_readable_page(hash);
        if (entry)
        {
            entry->count++;
        }
        i++;
    }
    spin_unlock(&readable_pages_lock);

    printk(KERN_INFO "Finished processing pages");

    // Count the number of groups of identical pages
    spin_lock(&hashed_readable_pages_lock);
    struct hash_entry *entry;
    list_for_each_entry(entry, &hashed_readable_pages_list, list)
    {
        if (entry->count > 1)
        {
            may_be_shared += entry->count;
            group_count++;
        }
        else
        {
            printk(KERN_INFO "loop: %d", entry->count);
        }
    }
    spin_unlock(&hashed_readable_pages_lock);

    initial_process->readonly_pages = may_be_shared;
    initial_process->readonly_groups = group_count;
    printk(KERN_INFO "may be shared: %d", may_be_shared);
    printk(KERN_INFO "groups: %d", group_count);

    kfree(desc);
    crypto_free_shash(tfm);

    printk(KERN_INFO "start free");
    // Free the hash list
    spin_lock(&hashed_readable_pages_lock);
    struct hash_entry *e;
    struct hash_entry *s;
    list_for_each_entry_safe(e, s, &hashed_readable_pages_list, list)
    {
        list_del(&e->list);
        kfree(e);
    }
    spin_unlock(&hashed_readable_pages_lock);

    if (list_empty(&hashed_readable_pages_list))
    {
        printk(KERN_INFO "freed");
    }
    printk(KERN_INFO "return");
    return 0;
}

/**
 * @brief given the intial_process, find if there are identical readable pages and append the value to the given struct
 */
static void find_duplicates(struct process_info *initial_process)
{
    struct mm_struct *mm;
    struct pid *pid_struct;
    struct vm_area_struct *vma;
    struct page *page;
    int i;
    unsigned long address;
    struct process_info *process;
    int nb = 0;
    struct list_head *pos;

    process = initial_process;
    // Iterate on every task
    while (process != NULL)
    {
        pid_struct = find_get_pid(process->pid);
        printk(KERN_INFO "Process Name : %s (pid = %d)", process->name, process->pid);
        mm = pid_task(pid_struct, PIDTYPE_PID)->mm;
        if (!mm)
        {
            printk(KERN_INFO "No memory management structure for the process.\n");
            return;
        }

        // Lock the memory map semaphore
        down_read(&mm->mmap_sem);

        for (vma = mm->mmap; vma; vma = vma->vm_next)
        {
            // Don't append the pages if they don't have the read authorization
            if (!(vma->vm_flags & VM_READ))
            {
                continue;
            }

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
                    struct page_ref *elem = kmalloc(sizeof(struct page_ref), GFP_KERNEL);
                    if (!elem)
                        continue;
                    elem->page = pte_page(*pte);
                    if (elem->page && !PageReserved(elem->page))
                    {
                        spin_lock(&readable_pages_lock);
                        INIT_LIST_HEAD(&elem->list);
                        list_add_tail(&elem->list, &readable_pages);
                        spin_unlock(&readable_pages_lock);
                    }
                }
                pte_unmap(pte);
            }
        }
        up_read(&mm->mmap_sem); // Release the memory map semaphore
        process = process->next;
    }
    spin_lock(&readable_pages_lock);
    list_for_each(pos, &readable_pages)
    {
        nb += 1;
    }
    spin_unlock(&readable_pages_lock);
    printk(KERN_INFO "%d", nb);
    if (count_readable_groups(initial_process) == 0)
        printk(KERN_INFO "HELLO");

    spin_lock(&readable_pages_lock);
    struct page_ref *p;
    struct page_ref *s;
    list_for_each_entry_safe(p, s, &readable_pages, list)
    {
        list_del(&p->list);
        kfree(p);
    }
    spin_unlock(&readable_pages_lock);

    // TODO: from the list readable_pages and determine the nb_of_group
    // TODO: append the result to the process info data structure
    return;
}

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
    if (task->mm)

    {
        info->total_pages = task->mm->total_vm;
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
    struct process_info *info;
    unsigned int bkt;
    int err = 0;

    rcu_read_lock();
    for_each_process(task)
    {
        if (task->mm)
        { // Ensure the task has a memory descriptor
            if (save_process_info(task)){
                err = -1;
                goto out;
            }
        }
    }

    hash_for_each(process_hash_table, bkt, info, hnode)
    {
        // TODO: integrate this function at the right place
        printk(KERN_INFO "BEFORE");
        find_duplicates(info);
        printk(KERN_INFO "AFTER");
    }

out:
    rcu_read_unlock();
    printk(KERN_INFO "gather_and_populate return code: %d", err);
    return err;
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
        // TODO: check if 32 is enough
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
    err = gather_and_populate_data();
    if (err)
    {
        printk(KERN_ALERT "[ERROR] gather_and_populate_data failed with error %d\n", err);
        proc_remove(our_proc_file);
        return err;
    }

    printk(KERN_INFO "gather_and_populate_data returned %d\n", err);
    return 0;
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
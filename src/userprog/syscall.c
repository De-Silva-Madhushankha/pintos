#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <list.h>
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"

#define CONSOLE_OUTPUT 1
#define KEYBOARD_INPUT 0
#define ERROR_STATUS -1

static void syscall_handler(struct intr_frame *);
static void syscall_exit(int status);
static tid_t syscall_exec(const char *file_name);
static int syscall_wait(tid_t tid);
static bool syscall_create(const char *file, unsigned initial_size);
static bool syscall_remove(const char *file);
static int syscall_open(const char *file);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void *buffer, unsigned size);
static int syscall_write(int fd, const void *buffer, unsigned size);
static void syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);
static void syscall_close(int fd);

void validate_ptr(const void *ptr);
void validate_str(const char *str);
void validate_buffer(const void *buffer, unsigned size);
int *get_kth_ptr(const void *ptr, int k);
struct file_descriptor *get_from_fd(int fd);

void syscall_init(void) {
    lock_init(&file_system_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED) {
    validate_ptr(f->esp);
    int syscall_type = *get_kth_ptr(f->esp, 0);

    switch (syscall_type) {
        case SYS_HALT:
            shutdown_power_off();
            break;
        case SYS_EXIT: {
            int status = *get_kth_ptr(f->esp, 1);
            syscall_exit(status);
            break;
        }
        case SYS_EXEC: {
            char *file_name = *(char **)get_kth_ptr(f->esp, 1);
            validate_str(file_name);
            f->eax = syscall_exec(file_name);
            break;
        }
        case SYS_WAIT: {
            tid_t tid = *get_kth_ptr(f->esp, 1);
            f->eax = syscall_wait(tid);
            break;
        }
        case SYS_CREATE: {
            char *file = *(char **)get_kth_ptr(f->esp, 1);
            validate_str(file);
            unsigned initial_size = *((unsigned *)get_kth_ptr(f->esp, 2));
            f->eax = syscall_create(file, initial_size);
            break;
        }
        case SYS_REMOVE: {
            char *file = *(char **)get_kth_ptr(f->esp, 1);
            validate_str(file);
            f->eax = syscall_remove(file);
            break;
        }
        case SYS_OPEN: {
            char *file = *(char **)get_kth_ptr(f->esp, 1);
            validate_str(file);
            f->eax = syscall_open(file);
            break;
        }
        case SYS_FILESIZE: {
            int fd = *get_kth_ptr(f->esp, 1);
            f->eax = syscall_filesize(fd);
            break;
        }
        case SYS_READ: {
            int fd = *get_kth_ptr(f->esp, 1);
            void *buffer = (void *)*get_kth_ptr(f->esp, 2);
            unsigned size = *((unsigned *)get_kth_ptr(f->esp, 3));
            validate_buffer(buffer, size);
            f->eax = syscall_read(fd, buffer, size);
            break;
        }
        case SYS_WRITE: {
            int fd = *get_kth_ptr(f->esp, 1);
            void *buffer = (void *)*get_kth_ptr(f->esp, 2);
            unsigned size = *((unsigned *)get_kth_ptr(f->esp, 3));
            validate_buffer(buffer, size);
            f->eax = syscall_write(fd, buffer, size);
            break;
        }
        case SYS_SEEK: {
            int fd = *get_kth_ptr(f->esp, 1);
            unsigned position = *((unsigned *)get_kth_ptr(f->esp, 2));
            syscall_seek(fd, position);
            break;
        }
        case SYS_TELL: {
            int fd = *get_kth_ptr(f->esp, 1);
            f->eax = syscall_tell(fd);
            break;
        }
        case SYS_CLOSE: {
            int fd = *get_kth_ptr(f->esp, 1);
            syscall_close(fd);
            break;
        }
        default:
            // Handle unknown syscall
            break;
    }
}

static void syscall_exit(int status) {
    struct thread *t = thread_current();
    t->exit_status = status;
    thread_exit();
}

static tid_t syscall_exec(const char *file_name) {
    struct thread *curr_t = thread_current();
    tid_t child_tid = process_execute(file_name);
    if (child_tid == TID_ERROR) return child_tid;

    struct thread *child_t;
    struct list_elem *child_elem;

    for (child_elem = list_begin(&curr_t->child_list); child_elem != list_end(&curr_t->child_list); child_elem = list_next(child_elem)) {
        child_t = list_entry(child_elem, struct thread, child_elem);
        if (child_t->tid == child_tid) break;
    }

    if (child_elem == list_end(&curr_t->child_list)) return ERROR_STATUS;

    sema_down(&child_t->start_sem);
    return child_t->load_status ? child_tid : ERROR_STATUS;
}

static int syscall_wait(tid_t tid) {
    return process_wait(tid);
}

static bool syscall_create(const char *file, unsigned initial_size) {
    lock_acquire(&file_system_lock);
    bool create_status = filesys_create(file, initial_size);
    lock_release(&file_system_lock);
    return create_status;
}

static bool syscall_remove(const char *file) {
    lock_acquire(&file_system_lock);
    bool remove_status = filesys_remove(file);
    lock_release(&file_system_lock);
    return remove_status;
}

static int syscall_open(const char *file) {
    struct file_descriptor *file_descriptor = malloc(sizeof(struct file_descriptor));
    struct file *file_ptr;
    struct thread *curr_t;

    lock_acquire(&file_system_lock);
    file_ptr = filesys_open(file);
    lock_release(&file_system_lock);

    if (file_ptr == NULL) {
        free(file_descriptor);
        return ERROR_STATUS;
    }

    curr_t = thread_current();
    file_descriptor->fd = curr_t->next_fd++;
    file_descriptor->file = file_ptr;
    list_push_back(&curr_t->open_fd_list, &file_descriptor->fd_elem);

    return file_descriptor->fd;
}

static int syscall_filesize(int fd) {
    struct file_descriptor *file_descriptor = get_from_fd(fd);
    if (file_descriptor == NULL) return ERROR_STATUS;

    lock_acquire(&file_system_lock);
    int file_size = file_length(file_descriptor->file);
    lock_release(&file_system_lock);

    return file_size;
}

static int syscall_read(int fd, void *buffer, unsigned size) {
    struct file_descriptor *file_descriptor;
    int read_size = 0;

    if (fd == KEYBOARD_INPUT) {
        for (unsigned i = 0; i < size; i++) {
            *((uint8_t *)buffer + i) = input_getc();
            read_size++;
        }
    } else if (fd == CONSOLE_OUTPUT) {
        return ERROR_STATUS;
    } else {
        file_descriptor = get_from_fd(fd);
        if (file_descriptor == NULL) return ERROR_STATUS;

        lock_acquire(&file_system_lock);
        read_size = file_read(file_descriptor->file, buffer, size);
        lock_release(&file_system_lock);
    }

    return read_size;
}

static int syscall_write(int fd, const void *buffer, unsigned size) {
    struct file_descriptor *file_descriptor;
    int written_size = 0;

    if (fd == CONSOLE_OUTPUT) {
        putbuf(buffer, size);
        written_size = size;
    } else if (fd == KEYBOARD_INPUT) {
        return ERROR_STATUS;
    } else {
        file_descriptor = get_from_fd(fd);
        if (file_descriptor == NULL) return ERROR_STATUS;

        lock_acquire(&file_system_lock);
        written_size = file_write(file_descriptor->file, buffer, size);
        lock_release(&file_system_lock);
    }

    return written_size;
}

static void syscall_seek(int fd, unsigned position) {
    struct file_descriptor *file_descriptor = get_from_fd(fd);
    if (file_descriptor != NULL) {
        lock_acquire(&file_system_lock);
        file_seek(file_descriptor->file, position);
        lock_release(&file_system_lock);
    }
}

static unsigned syscall_tell(int fd) {
    struct file_descriptor *file_descriptor = get_from_fd(fd);
    if (file_descriptor == NULL) return 0;

    lock_acquire(&file_system_lock);
    unsigned pos = file_tell(file_descriptor->file);
    lock_release(&file_system_lock);

    return pos;
}

static void syscall_close(int fd) {
    struct file_descriptor *file_descriptor = get_from_fd(fd);
    if (file_descriptor != NULL) {
        lock_acquire(&file_system_lock);
        file_close(file_descriptor->file);
        lock_release(&file_system_lock);

        list_remove(&file_descriptor->fd_elem);
        free(file_descriptor);
    }
}

void validate_ptr(const void *ptr) {
    struct thread *curr_t = thread_current();

    if (ptr == NULL || is_kernel_vaddr(ptr) || pagedir_get_page(curr_t->pagedir, ptr) == NULL) {
        syscall_exit(ERROR_STATUS);
    }
}

void validate_str(const char *str) {
    validate_ptr((void *)str);
    for (int k = 0; *((char *)str + k) != 0; k++) {
        validate_ptr((void *)((char *)str + k + 1));
    }
}

void validate_buffer(const void *buffer, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        validate_ptr((void *)((char *)buffer + i));
    }
}

int *get_kth_ptr(const void *ptr, int k) {
    int *next_ptr = (int *)ptr + k;
    validate_ptr((void *)next_ptr);
    validate_ptr((void *)(next_ptr + 1));
    return next_ptr;
}

struct file_descriptor *get_from_fd(int fd) {
    struct thread *curr_t = thread_current();
    struct file_descriptor *file_descriptor;
    struct list_elem *fd_elem;

    for (fd_elem = list_begin(&curr_t->open_fd_list); fd_elem != list_end(&curr_t->open_fd_list); fd_elem = list_next(fd_elem)) {
        file_descriptor = list_entry(fd_elem, struct file_descriptor, fd_elem);
        if (file_descriptor->fd == fd) return file_descriptor;
    }
    return NULL;
}

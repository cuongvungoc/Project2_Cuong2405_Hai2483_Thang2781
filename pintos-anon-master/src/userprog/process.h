#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "filesys/directory.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* Used to synchronize and wait for load to complete */
struct load_synch
  {
    char *filename;
    struct semaphore sema;
    bool success;
    struct dir *parent_working_dir;
  };

#endif /* userprog/process.h */

// Check git

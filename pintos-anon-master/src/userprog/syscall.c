#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

// # define max_syscall 20
// static void (*syscalls[max_syscall])(struct intr_frame *);

// void sys_write(struct intr_frame* f); /* syscall write */

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // syscalls[SYS_WRITE] = &sys_write;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

// /* Do system write, Do writing in stdout and write in files */
// void 
// sys_write (struct intr_frame* f)
// {
//   uint32_t *user_ptr = f->esp;
//   check_ptr2 (user_ptr + 7);
//   check_ptr2 (*(user_ptr + 6));
//   *user_ptr++;
//   int temp2 = *user_ptr;
//   const char * buffer = (const char *)*(user_ptr+1);
//   off_t size = *(user_ptr+2);
//   if (temp2 == 1) {
//     /* Use putbuf to do testing */
//     putbuf(buffer,size);
//     f->eax = size;
//   }
//   else
//   {
//     /* Write to Files */
//     struct thread_file * thread_file_temp = find_file_id (*user_ptr);
//     if (thread_file_temp)
//     {
//       acquire_lock_f ();
//       f->eax = file_write (thread_file_temp->file, buffer, size);
//       release_lock_f ();
//     } 
//     else
//     {
//       f->eax = 0;
//     }
//   }
// }

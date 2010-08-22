/*
  Copyright notice
  ================
  
  Copyright (C) 2010
      Lorenzo  Martignoni <martignlo@gmail.com>
      Roberto  Paleari    <roberto.paleari@gmail.com>
  
  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.
  
  ProcessTap is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
*/

#ifndef __processtap_h__
#define __processtap_h__

#include "bloomfilter.h"

#if !defined(__i386__) && !defined(__x86_64__)
#error "unsupported cpu"
#endif

#ifdef __cplusplus
extern "C" {
#endif

  typedef enum { 
    FUNCTION_CALL = 1,
    FUNCTION_RETURN  = 2,
    SYSCALL_ENTRY  = 4,
    SYSCALL_EXIT   = 8,
    MEMORY_READ    = 16,
    MEMORY_WRITE   = 32,
    MEMORY_EXECUTE = 64,
  } ptap_event_type_t;

  typedef enum {
#if defined(__i386__) || defined(__x86_64__)
    RAX = 0,
    RBX,
    RCX,
    RDX,
    RSI,
    RDI,
    RSP,
    RBP,
    RFLAGS,
    RIP,
#endif
#if defined(__i386__)
    EAX = 0,
    EBX,
    ECX,
    EDX,
    ESI,
    EDI,
    ESP,
    EBP,
    EFLAGS,
    EIP,
#elif defined(__x86_64__)
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
#endif
  } ptap_reg_t;

  extern unsigned int   event_filter;
  extern bloomfilter_t *process_thread_filter;
  extern bloomfilter_t *module_filter;
  extern bloomfilter_t *function_filter;
  extern bloomfilter_t *syscall_filter;

  typedef int (*ptap_read_reg_t)(ptap_reg_t, void **);
  typedef int (*ptap_write_reg_t)(ptap_reg_t, void **);
  typedef int (*ptap_read_mem_t)(void *, size_t, unsigned char *);
  typedef int (*ptap_write_mem_t)(void *, size_t, unsigned char *);

  int ptap_init(const char *exe, const char *, 
		ptap_read_reg_t, ptap_write_reg_t, 
		ptap_read_mem_t, ptap_write_mem_t);
  int ptap_fini();

  int ptap_dispatch_syscall_entry(int pid, int tid, void *instrptr, void *stackptr, void *sysno);
  int ptap_dispatch_syscall_exit(int pid, int tid, void *instrptr, void *stackptr, void *sysno, void *retval);
  int ptap_dispatch_function_call(int pid, int tid, void *instrptr, void *stackptr, void *funcaddr);
  int ptap_dispatch_function_return(int pid, int tid, void *instrptr, void *stackptr, void *funcaddr, void *retaddr, void *retval);

  int ptap_add_module(int pid, const char *name, void *base, size_t size, int is_lib);
  int ptap_del_module(void *base);
  
  int ptap_add_symbol(const char *name, void *base, size_t size);
  int ptap_del_symbol(void *base);
  
  inline int ptap_instrument_event(unsigned int e) {
    return (e & event_filter) > 0;
  }
  
  inline int ptap_instrument_process_thread(int id) {
    return bloomfilter_contain(process_thread_filter, (unsigned char *) &id, sizeof(id));
  }

  inline int ptap_instrument_module(void *addr_) {
    unsigned long addr = (unsigned long) addr_;

    return addr < 0x10000000;
    // addr &= ~0xFFF;
    // return bloomfilter_contain(module_filter, (unsigned char *) &addr, sizeof(addr));
  }

  inline int ptap_instrument_function(void *funcaddr) {
    return 1;
    // return bloomfilter_contain(function_filter, (unsigned char *) &funcaddr, sizeof(funcaddr));
  }

  inline int ptap_instrument_syscall(void *sysno) {
    return bloomfilter_contain(syscall_filter, (unsigned char *) &sysno, sizeof(sysno));
  }

#if 0
  inline int ptap_instrument_memory_read(void *addr, size_t size) {
    unsigned char *tmp;

    for (tmp = (unsigned char *) addr; tmp < ((unsigned char *) addr) + size; tmp++) {
      if (!bloomfilter_contain(memory_read_filter, (unsigned char *) &tmp, sizeof(tmp)))
	return 0;
    }

    return 1;
  }

  inline int ptap_instrument_memory_write(void *addr, size_t size) {
    unsigned char *tmp;

    for (tmp = (unsigned char *) addr; tmp < ((unsigned char *) addr) + size; tmp++) {
      if (!bloomfilter_contain(memory_write_filter, (unsigned char *) &tmp, sizeof(tmp)))
	return 0;
    }
    return 1;
  }
#endif

#ifdef __cplusplus
};
#endif

#endif

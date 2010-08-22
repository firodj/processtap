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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

// Normalize CPU registers for both 32-bit and 64-bit systems
#if defined(__x86_64__)
// 64-bit system
#define REGISTER_RSP    LEVEL_BASE::REG_RSP
#define REGISTER_RBP    LEVEL_BASE::REG_RBP
#define REGISTER_RIP    LEVEL_BASE::REG_RIP
#define REGISTER_RFLAGS LEVEL_BASE::REG_RFLAGS
#elif defined(__i386__)
// 32-bit system
#define REGISTER_RSP    LEVEL_BASE::REG_ESP
#define REGISTER_RBP    LEVEL_BASE::REG_EBP
#define REGISTER_RIP    LEVEL_BASE::REG_EIP
#define REGISTER_RFLAGS LEVEL_BASE::REG_EFLAGS
#else
#error "[!] Unknown architecture"
#endif

namespace PTAP {
#include "processtap.h"
}
#define ptap_reg_t PTAP::ptap_reg_t

#include <pin.H>

char *exe, *tap;

typedef struct {
  void *stackptr;
  void *funcaddr;
} callstack_t;

#define CALLSTACK_MAX_DEPTH 1024

class thread_data_t {
public:
  CONTEXT *context;
  int callstack_depth;
  callstack_t callstack[CALLSTACK_MAX_DEPTH];
  bool canrun;
  bool dirty;

  thread_data_t(void) { context = NULL; callstack_depth = 0; canrun = true; dirty = false; };
};

static CONTEXT *ctx = NULL;
static TLS_KEY tls_key;

// function to access thread-specific data
thread_data_t* get_tls(THREADID threadid) {
    thread_data_t* tdata = 
          static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
    return tdata;
}

// ****************************************************************************
// Callbacks used by ptap probes to inspect the status of the process
// ****************************************************************************

static inline REG reg2REG(ptap_reg_t r_) {
  REG r;

  switch (r_) {
#if defined(__i386__)
  case PTAP::EAX:
    r = LEVEL_BASE::REG_EAX;
    break;
  case PTAP::EBX:
    r = LEVEL_BASE::REG_EBX;
    break;
  case PTAP::ECX:
    r = LEVEL_BASE::REG_ECX;
    break;
  case PTAP::EDX:
    r = LEVEL_BASE::REG_EDX;
    break;
  case PTAP::ESI:
    r = LEVEL_BASE::REG_ESI;
    break;
  case PTAP::EDI:
    r = LEVEL_BASE::REG_EDI;
    break;
  case PTAP::ESP:
    r = LEVEL_BASE::REG_ESP;
    break;
  case PTAP::EBP:
    r = LEVEL_BASE::REG_EBP;
    break;
  case PTAP::EFLAGS:
    r = LEVEL_BASE::REG_EFLAGS;
    break;
  case PTAP::EIP:
    r = LEVEL_BASE::REG_EIP;
    break;
#elif defined(__x86_64__)
  case PTAP::RAX:
    r = LEVEL_BASE::REG_RAX;
    break;
  case PTAP::RBX:
    r = LEVEL_BASE::REG_RBX;
    break;
  case PTAP::RCX:
    r = LEVEL_BASE::REG_RCX;
    break;
  case PTAP::RDX:
    r = LEVEL_BASE::REG_RDX;
    break;
  case PTAP::RSI:
    r = LEVEL_BASE::REG_RSI;
    break;
  case PTAP::RDI:
    r = LEVEL_BASE::REG_RDI;
    break;
  case PTAP::RSP:
    r = LEVEL_BASE::REG_RSP;
    break;
  case PTAP::RBP:
    r = LEVEL_BASE::REG_RBP;
    break;
  case PTAP::RFLAGS:
    r = LEVEL_BASE::REG_RFLAGS;
    break;
  case PTAP::RIP:
    r = LEVEL_BASE::REG_RIP;
    break;
  case PTAP::R8:
    r = LEVEL_BASE::REG_R8;
    break;
  case PTAP::R9:
    r = LEVEL_BASE::REG_R9;
    break;
  case PTAP::R10:
    r = LEVEL_BASE::REG_R10;
    break;
  case PTAP::R11:
    r = LEVEL_BASE::REG_R11;
    break;
  case PTAP::R12:
    r = LEVEL_BASE::REG_R12;
    break;
  case PTAP::R13:
    r = LEVEL_BASE::REG_R13;
    break;
  case PTAP::R14:
    r = LEVEL_BASE::REG_R14;
    break;
  case PTAP::R15:
    r = LEVEL_BASE::REG_R15;
    break;
#endif
  default:
    printf("REG: %d\n", r_);
    assert(false);
  }

  return r;
}

int read_reg(ptap_reg_t r, void **v) {
  *v = (void *) PIN_GetContextReg(get_tls(PIN_ThreadId())->context, reg2REG(r));
  return 1;
}

int write_reg(ptap_reg_t r, void **v) {
  get_tls(PIN_ThreadId())->dirty = true;

  PIN_SetContextReg(get_tls(PIN_ThreadId())->context, reg2REG(r), *(ADDRINT*) v);
  return 1;
}

int read_mem(void *addr, size_t size, unsigned char *buf) {
  memcpy(buf, addr, size);
  return 1;
}

int write_mem(void *addr, size_t size, unsigned char *buf) {
  memcpy(addr, buf, size);
  return 1;
}

// ****************************************************************************
// Call stack handling
// ****************************************************************************

static inline void push_stack_frame(int tid, void * stackptr, void * funcaddr) {
  thread_data_t *tdata = get_tls(tid);
  
  assert(tdata->callstack_depth < CALLSTACK_MAX_DEPTH);

  tdata->callstack[tdata->callstack_depth].stackptr = stackptr;
  tdata->callstack[tdata->callstack_depth].funcaddr = funcaddr;
  tdata->callstack_depth++;
}

static inline void *pop_stack_frame(int tid, void * stackptr) {
  thread_data_t *tdata = get_tls(tid);

  while (--tdata->callstack_depth >= 0 && tdata->callstack[tdata->callstack_depth].stackptr != stackptr) {
    ;
  }

  if (tdata->callstack_depth >= 0 && tdata->callstack[tdata->callstack_depth].stackptr == stackptr) {
    return tdata->callstack[tdata->callstack_depth].funcaddr;
  } else {
    return NULL;
  }
}

static inline void *top_stack_frame(int tid, void * stackptr) {
  thread_data_t *tdata = get_tls(tid);
  int depth = tdata->callstack_depth;

  while (--depth > 0 && tdata->callstack[depth].stackptr != stackptr) {
    ;
  }

  if (depth >= 0 && tdata->callstack[depth].stackptr == stackptr) {
    return tdata->callstack[depth].funcaddr;
  } else {
    return NULL;
  }
}

static inline int depth_stack_frame(int tid) {
  thread_data_t *tdata = get_tls(tid);

  return tdata->callstack_depth;
}

// ****************************************************************************
// Instrumentation for event notification
// ****************************************************************************

static ADDRINT callback_check(THREADID tid) {
  ADDRINT r;

  r = get_tls(tid)->canrun ? 1 : 0;

  if (!r)
    get_tls(tid)->canrun = true;

  return r;
}

static void callback_commit(THREADID tid) {
  assert(callback_check(tid));

  if (get_tls(tid)->dirty) {
    get_tls(tid)->canrun = false;
    get_tls(tid)->dirty  = false;
    PIN_ExecuteAt(get_tls(tid)->context);
  }
}

static void function_call(THREADID tid, CONTEXT *ctx_, ADDRINT instrptr,
			   ADDRINT stackptr, ADDRINT funcaddr) {
  int r;

  if (PTAP::ptap_instrument_event(PTAP::FUNCTION_RETURN))
    push_stack_frame(tid, (void *) (stackptr - sizeof(void*)), (void *) funcaddr);
  
  if (!PTAP::ptap_instrument_module((void *) instrptr) || 
      !PTAP::ptap_instrument_function((void *) funcaddr))
    return;

  get_tls(tid)->context = ctx_;

  r = PTAP::ptap_dispatch_function_call((int) 0, (int) tid, (void *) instrptr,
					 (void *) stackptr, (void *) funcaddr);

  if (r) {
    abort();
  }
}

static void function_return(THREADID tid, CONTEXT *ctx_, ADDRINT instrptr,
			    ADDRINT stackptr, ADDRINT retval) {
  ADDRINT retaddr;
  void *funcaddr = NULL;
  int r;

  funcaddr = pop_stack_frame(tid, (void *) stackptr);
  retaddr = *((ADDRINT *) stackptr);
  
  if (!PTAP::ptap_instrument_module((void *) retaddr))
    return;

  if (!funcaddr || !PTAP::ptap_instrument_function((void *) funcaddr))
    return;

  get_tls(tid)->context = ctx_;

  r = PTAP::ptap_dispatch_function_return((int) 0, (int) tid, (void *) instrptr,
					  (void *) stackptr, 
					  (void *) funcaddr, (void *) retaddr, (void *) retval);

  if (r) {
    abort();
  }

  callback_commit(tid);
}

static void syscall_entry(THREADID tid, CONTEXT *ctx_, SYSCALL_STANDARD std, VOID *v) {
  void *sysno = (void *) PIN_GetSyscallNumber(ctx_, std);
  void *stackptr = (void *) PIN_GetContextReg(ctx_, REGISTER_RSP);
  void *instrptr;
  int r;

  if(!callback_check(tid)) return;

  if (PTAP::ptap_instrument_event(PTAP::SYSCALL_EXIT))
    push_stack_frame(tid, stackptr, sysno);

  if (!PTAP::ptap_instrument_syscall(sysno))
    return;

  get_tls(tid)->context = ctx_;

  instrptr = (void *) PIN_GetContextReg(ctx_, REGISTER_RIP);

  r = PTAP::ptap_dispatch_syscall_entry((int) 0, (int) tid, instrptr,
					stackptr, sysno);

  if (r) {
    abort();
  }
}

static void syscall_exit(THREADID tid, CONTEXT *ctx_, SYSCALL_STANDARD std, VOID *v) {
  void *stackptr = (void *) PIN_GetContextReg(ctx_, REGISTER_RSP);
  void *instrptr;
  void *retval;
  void *sysno;
  int r;

  if(!callback_check(tid)) return;

  sysno = pop_stack_frame(tid, stackptr);

  if (!PTAP::ptap_instrument_syscall(sysno))
    return;

  instrptr = (void *) PIN_GetContextReg(ctx_, REGISTER_RIP);
  retval = (void *) PIN_GetSyscallReturn(ctx_, std);
  get_tls(tid)->context = ctx_;
  r = PTAP::ptap_dispatch_syscall_exit((int) 0, (int) tid, instrptr,
				       stackptr, sysno, retval);

  if (r) {
    abort();
  }
}

static void branch(THREADID tid, CONTEXT *ctx_, ADDRINT instrptr, ADDRINT stackptr, BOOL pred,
		   ADDRINT targetaddr, ADDRINT fallthroughaddr) {
  ctx = ctx_;
}

static void memory_read(THREADID tid, CONTEXT *ctx_, ADDRINT instrptr, ADDRINT stackptr,
			ADDRINT readaddr, UINT32 readlen) {
  ctx = ctx_;
}

static void memory_write(THREADID tid, CONTEXT *ctx_, ADDRINT instrptr, ADDRINT stackptr,
			 ADDRINT writeaddr, UINT32 writelen) {
  ctx = ctx_;
}

#define event(x) PTAP::ptap_instrument_event(PTAP::x)
static VOID instruction(INS ins, void *a) {
  if (INS_IsCall(ins) && (event(FUNCTION_RETURN) || event(FUNCTION_CALL))) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) callback_check, IARG_THREAD_ID, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR) function_call, 
		       IARG_THREAD_ID, 
		       IARG_CONTEXT, 
		       IARG_INST_PTR, 
		       IARG_REG_VALUE, REG_STACK_PTR,
		       IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, 
		       IARG_END);
  } else if (INS_IsRet(ins) && event(FUNCTION_RETURN)) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) callback_check, IARG_THREAD_ID, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR) function_return, 
		       IARG_THREAD_ID, 
		       IARG_CONTEXT, 
		       IARG_INST_PTR, 
		       IARG_REG_VALUE, REG_STACK_PTR,
		       IARG_FUNCRET_EXITPOINT_VALUE, 
		       IARG_END);
  } else if (INS_IsBranch(ins) && 0) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) callback_check, IARG_THREAD_ID, IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) branch, 
     		   IARG_THREAD_ID, 
		   IARG_CONTEXT, 
		   IARG_INST_PTR, 
     		   IARG_BRANCH_TAKEN, 
		   IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, 
		   IARG_END);
  } else if (INS_IsMemoryRead(ins) && 0 && event(MEMORY_READ)) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) callback_check, IARG_THREAD_ID, IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) memory_read, 
		   IARG_THREAD_ID, 
		   IARG_CONTEXT, 
		   IARG_INST_PTR, 
		   IARG_REG_VALUE, REG_STACK_PTR,
		   IARG_MEMORYREAD_EA, 
		   IARG_MEMORYREAD_SIZE, 
		   IARG_END);
    if (INS_HasMemoryRead2(ins)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) callback_check, IARG_THREAD_ID, IARG_END);
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) memory_read, 
		     IARG_THREAD_ID, 
		     IARG_CONTEXT, 
		     IARG_INST_PTR, 
		     IARG_REG_VALUE, REG_STACK_PTR,
		     IARG_MEMORYREAD2_EA, 
		     IARG_MEMORYREAD_SIZE,
		     IARG_END);
    }
  } else if (INS_IsMemoryWrite(ins) && 0 && event(MEMORY_WRITE)) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) callback_check, IARG_THREAD_ID, IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) memory_write, 
     		   IARG_THREAD_ID, 
		   IARG_CONTEXT, 
		   IARG_INST_PTR, IARG_REG_VALUE, REG_STACK_PTR,
     		   IARG_MEMORYWRITE_EA, 
		   IARG_MEMORYWRITE_SIZE, 
		   IARG_END);
  } 
}

VOID fini(INT32 code, VOID *v) {
  PTAP::ptap_fini();
}

VOID allocate_tls(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) {
  thread_data_t* tdata = new thread_data_t;
  PIN_SetThreadData(tls_key, tdata, threadid);
}

VOID image_load(IMG img, VOID *v) {
  PTAP::ptap_add_module(getpid(), IMG_Name(img).c_str(), (void*) IMG_LowAddress(img), IMG_SizeMapped(img), !IMG_IsMainExecutable(img));
}

// Pin calls this function every time a new img is unloaded
// You can't instrument an image that is about to be unloaded
VOID image_unload(IMG img, VOID *v) {
  ;
}

int main(int argc, char **argv) {
  char *p;
  int i;

  PIN_InitSymbols();
  PIN_Init(argc, argv);
  PIN_AddFiniFunction(fini, 0);

  tls_key = PIN_CreateThreadDataKey(0);

  PIN_SetSyntaxATT();

  // Parse arguments
  p = tap = exe = NULL;

  for (i=0; i<argc; i++) {
    if (!strcmp(argv[i], "--")) {
      exe = argv[i+1];
      break;
    }
  }  

  fprintf(stderr, "[*] Executable file: %s\n", exe);

  for (i=0; i<argc; i++) {
    if (!strcmp(argv[i], "processtap_pin")) {
      p = argv[i];
      tap = argv[i+1];
      break;
    }
  }

  if (p == NULL || !strcmp(tap, "--")) {
    fprintf(stderr, "[!] ProcessTap needs the PTAP filename as an argument\n");
    return -1;
  }

  fprintf(stderr, "[*] PTAP file: %s\n", tap);
  i = PTAP::ptap_init(exe, tap, read_reg, write_reg, read_mem, write_mem);
  if (i == -1) {
    fprintf(stderr, "[!] ProcessTap initialization failed!\n");
    return -1;
  }
  
  PIN_AddThreadStartFunction(allocate_tls, 0);
  INS_AddInstrumentFunction(instruction, 0);
  IMG_AddInstrumentFunction(image_load, 0);
  IMG_AddUnloadFunction(image_unload, 0);

  if (event(SYSCALL_ENTRY) || event(SYSCALL_EXIT))
    PIN_AddSyscallEntryFunction(syscall_entry, 0);
  if (event(SYSCALL_EXIT))
    PIN_AddSyscallExitFunction(syscall_exit, 0);

  PIN_StartProgram();
  return 0;
}

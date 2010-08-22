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

#include <Python.h>
#include <assert.h>
#include <dlfcn.h>

#include "processtap.h"
#include "bloomfilter.h"

#define PyModule(m) __module_ ## m
#define PyAttribute(m, a) __module_ ## m_ ## a

#define CHECK_ARG(a) {					\
    if (!(a)) {						\
      Py_DECREF(pArgs);					\
      Py_DECREF(PTAPPythonObjects.pModuleProcessTap);	\
      fprintf(stderr, "Cannot convert argument\n");	\
      return -1;					\
    }							\
  }

#define IMPORT_MODULE(m) {					\
    PyModule(m) = PyImport_ImportModule(# m);			\
    if (!PyModule(m)) {						\
      PyErr_Print();						\
      fprintf(stderr, "[!] Failed to load '%s'\n", # m);	\
      return -1;						\
    }								\
  }

#define LOAD_FUNCTION(m, f) {						\
    PyAttribute(m, f) = PyObject_GetAttrString(PyModule(m), #f);	\
    if (!(PyAttribute(m, f) && PyCallable_Check(PyAttribute(m, f)))) {	\
      fprintf(stderr, "Cannot find function '%s' in '%s'\n", # f, # m); \
      return -1;							\
    }									\
  }

#define LOAD_CLASS(m, c) {						\
    PyAttribute(m, c) = PyObject_GetAttrString(PyModule(m), #c);	\
    if (!PyAttribute(m, c) || !PyClass_Check(PyAttribute(m, c))) {	\
      fprintf(stderr, "Cannot find class %s\n", #c);			\
      return -1;							\
    }									\
  }

#define CALL_FUNCTION(m, f, fmt, ...) \
  PyObject_CallFunction(PyAttribute(m, f), fmt, __VA_ARGS__);

PyObject *PyModule(processtap) = NULL;
PyObject *PyModule(event) = NULL;
PyObject *PyModule(probe) = NULL;
PyObject *PyModule(symbol) = NULL;
PyObject *PyAttribute(processtap, init) = NULL;
PyObject *PyAttribute(processtap, dispatch) = NULL;
PyObject *PyAttribute(symbol, add_module) = NULL;
PyObject *PyAttribute(event, function_entry) = NULL;
PyObject *PyAttribute(event, function_exit) = NULL;
PyObject *PyAttribute(event, syscall_entry) = NULL;
PyObject *PyAttribute(event, syscall_exit) = NULL;

// Callbacks
PyObject *stub_read_reg(PyObject *self, PyObject *args);
PyObject *stub_read_mem(PyObject *self, PyObject *args);
PyObject *stub_write_reg(PyObject *self, PyObject *args);
PyObject *stub_write_mem(PyObject *self, PyObject *args);
static PyMethodDef callbacks[] = {
  {"read_reg",   stub_read_reg,  METH_VARARGS, "Reads CPU registers."},
  {"write_reg",  stub_write_reg, METH_VARARGS, "Writes CPU registers."},
  {"read_mem",   stub_read_mem,  METH_VARARGS, "Reads memory."},
  {"write_mem",  stub_write_reg, METH_VARARGS, "Writes memory."},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};
static ptap_read_reg_t read_reg = NULL;
static ptap_write_reg_t write_reg = NULL;
static ptap_read_mem_t read_mem = NULL;
static ptap_write_mem_t write_mem = NULL;

// Filters
unsigned int  event_filter = 0;
bloomfilter_t *process_thread_filter = NULL;
bloomfilter_t *module_filter = NULL;
bloomfilter_t *function_filter = NULL;
bloomfilter_t *syscall_filter = NULL;

// Wrappers to callback
PyObject *stub_read_reg(PyObject *self, PyObject *args) {
  int reg;
  void *value;
  PyObject *pyvalue;

  if (!PyArg_ParseTuple(args, "i", &reg))
    return NULL;

  read_reg(reg, &value);
  pyvalue = PyLong_FromUnsignedLong((unsigned long) value);

  return pyvalue;
}

PyObject *stub_read_mem(PyObject *self, PyObject *args) {
  unsigned long addr;
  size_t len;
  unsigned char *buf;
  int r;
  PyObject *pybuf;

  if (!PyArg_ParseTuple(args, "kk", &addr, &len))
    return NULL;

  buf = (unsigned char *) malloc(len);
  if (!buf)
    return NULL;

  r = read_mem((void *) addr, len, buf);
  if (!r) {
    Py_XINCREF(Py_None);
    return Py_None;
  }

  pybuf = PyString_FromStringAndSize((const char *) buf, len);

  return pybuf;
}

PyObject *stub_write_reg(PyObject *self, PyObject *args) {
  int reg;
  unsigned long value;

  if (!PyArg_ParseTuple(args, "ik", &reg, &value))
    return NULL;

  write_reg(reg, (void **) &value);

  Py_XINCREF(Py_None);
  return Py_None;  
}

PyObject *stub_write_mem(PyObject *self, PyObject *args) {
  unsigned long addr;
  size_t len, len_;
  unsigned char *buf;
  int r;

  if (!PyArg_ParseTuple(args, "kis#", &addr, &len, &buf, &len_))
    return NULL;

  r = write_mem((void *) addr, len, buf);

  Py_XINCREF(Py_None);
  return Py_None;
}

#define alloc_filter(n, m, k) { \
    n = bloomfilter_init(m, k);	\
    if (!n) 			\
      return 0;			\
    bloomfilter_fill(n);	\
  } 

static int ptap_init_filters() {
#if 0
  PyObject *pArgs, *pValue, *pValue2;
  Py_ssize_t s;
  void *val;
#endif

  alloc_filter(process_thread_filter, 1024, 2);
  alloc_filter(module_filter, 1024*32, 2);
  alloc_filter(function_filter, 1024*4, 2);
  alloc_filter(syscall_filter, 1024*4, 2);

#if 0
  pArgs = PyTuple_New(1);

  pValue = PyInt_FromLong(event);					
  PyTuple_SetItem(pArgs, 0, pValue);					
  pValue = PyObject_CallObject(PTAPPythonObjects.pFunctionFilterEvent, pArgs); 
  if (!(pValue && PyList_Check(pValue))) {
    PyErr_Print();
    return -1;								
  }									
  
  for (s = 0; s < PyList_Size(pValue); s++) {				
    pValue2 = PyList_GetItem(pValue, s);				
    if (!(pValue2 && (PyInt_Check(pValue2) || (pValue2 == Py_None)))) {				
      PyErr_Print();
      return -1;							
    }									

    if (pValue2 == Py_None) {						
      bloomfilter_fill(filter);						
      Py_DECREF(pValue2);						
      break;
    } else {                                                   
      val = (void *) PyInt_AsLong(pValue2);				       
      bloomfilter_add(filter, (unsigned char *) &val, sizeof(void *));
      Py_DECREF(pValue2);
    }
  }

  Py_DECREF(pValue);
  Py_DECREF(pArgs);
#endif

  return 1;
}

int ptap_init(const char *exe, const char *tap, 
	      ptap_read_reg_t rr, ptap_write_reg_t wr, 
	      ptap_read_mem_t rm, ptap_write_mem_t wm) {
  PyObject *pValue;
  void *h;

  read_reg = rr;
  read_mem = rm;
  write_reg = wr;
  write_mem = wm;

  /* make symbols available to subsequently loaded .so */
  h = dlopen("/usr/lib/libpython2.6.so", RTLD_LAZY | RTLD_GLOBAL);
  if (!h)
    return -1;
  Py_InitializeEx(0);
  
  IMPORT_MODULE(processtap);
  IMPORT_MODULE(event);
  IMPORT_MODULE(probe);
  IMPORT_MODULE(symbol);

  LOAD_FUNCTION(processtap, init);
  LOAD_FUNCTION(processtap, dispatch);
  LOAD_FUNCTION(symbol, add_module);

  LOAD_CLASS(event, function_entry);
  LOAD_CLASS(event, function_exit);
  LOAD_CLASS(event, syscall_entry);
  LOAD_CLASS(event, syscall_exit);

  pValue = Py_InitModule("processtapmethods", callbacks);
  pValue = CALL_FUNCTION(processtap, init, "ssO", exe, tap, pValue);

  if (PyErr_Occurred()) {
    PyErr_Print();
    return -1;
  }

  if (!pValue && !PyInt_Check(pValue)) {
    return -1;
  }

  event_filter = PyInt_AsLong(pValue);

  Py_XDECREF(pValue);

  if (!ptap_init_filters()) {
    fprintf(stderr, "Unable to init filters\n");
    return -1;
  }

  return 0;
}

int ptap_fini() {
  fprintf(stderr, "[*] ProcessTap is finalizing...\n");

  Py_XDECREF(PyAttribute(processtap, init));
  Py_XDECREF(PyAttribute(processtap, dispatch));
  Py_XDECREF(PyModule(processtap));
  Py_XDECREF(PyAttribute(event, function_entry));
  Py_XDECREF(PyAttribute(event, function_exit));
  Py_XDECREF(PyAttribute(event, syscall_entry));
  Py_XDECREF(PyAttribute(event, syscall_exit));
  Py_XDECREF(PyModule(event));

  Py_Finalize();

  return 0;
}

int ptap_add_module(int pid, const char *name, void *base, size_t size, int is_lib) {
  CALL_FUNCTION(symbol, add_module, "iskki", pid, name, base, size, is_lib);
  if (PyErr_Occurred()) {
    PyErr_Print();
    return -1;
  }
  return 1;
}

int ptap_del_module(void *base) {
  return 1;
}
  
int ptap_add_symbol(const char *name, void *base, size_t size) {
  return 1;
}

int ptap_del_symbol(void *base) {
  return 1;
}

static inline int ptap_dispatch(PyObject *e) {
  PyObject_CallFunctionObjArgs(PyAttribute(processtap, dispatch), e, NULL);

  if (PyErr_Occurred()) {
    PyErr_Print();
    return -1;
  }

  Py_XDECREF(e);

  return 0;
}

int ptap_dispatch_syscall_entry(int pid, int tid, void *instptr, void *stackptr, void *sysno) {
  PyObject *event;

  /* Instantiate the event object */
  event = CALL_FUNCTION(event, syscall_entry, "iikki", pid, tid, (unsigned long) instptr, 
			(unsigned long) stackptr, (int) *((unsigned int *) &sysno) & 0xFFFFFFFF);

  if (PyErr_Occurred()) {
    PyErr_Print();
    return -1;
  }

  /* Dispatch the event */
  return ptap_dispatch(event);
}

int ptap_dispatch_syscall_exit(int pid, int tid, void *instptr, void *stackptr, void *sysno, void *retval) {
  PyObject *event;

  /* Instantiate the event object */
  event = CALL_FUNCTION(event, syscall_exit, "iikkik", pid, tid, (unsigned long) instptr, 
			(unsigned long) stackptr, (int) *((unsigned int *) &sysno) & 0xFFFFFFFF,
			(unsigned long) retval);

  if (PyErr_Occurred()) {
    PyErr_Print();
    return -1;
  }

  /* Dispatch the event */
  return ptap_dispatch(event);
}

int ptap_dispatch_function_call(int pid, int tid, void *instptr, void *stackptr, void *funcaddr) {
  PyObject *event;

  /* Instantiate the event object */
  event = CALL_FUNCTION(event, function_entry, "iikkk", pid, tid, (unsigned long) instptr, 
			(unsigned long) stackptr, (unsigned long) funcaddr);

  if (PyErr_Occurred()) {
    PyErr_Print();
    return -1;
  }

  /* Dispatch the event */
  return ptap_dispatch(event);
}

int ptap_dispatch_function_return(int pid, int tid, void *instptr, void *stackptr, void *funcaddr, void *retaddr, void *retval) {
  PyObject *event;

  /* Instantiate the event object */
  event = CALL_FUNCTION(event, function_exit, "iikkkkk", pid, tid, (unsigned long) instptr, 
			(unsigned long) stackptr, (unsigned long) funcaddr, (unsigned long) retaddr, (unsigned long) retval);

  if (PyErr_Occurred()) {
    PyErr_Print();
    return -1;
  }

  /* Dispatch the event */
  return ptap_dispatch(event);
}

/*******************************************************************
 * File automatically generated by rebuild_wrappers.py (v2.5.0.24) *
 *******************************************************************/
#ifndef __wrappedldlinuxTYPES_H_
#define __wrappedldlinuxTYPES_H_

#ifndef LIBNAME
#error You should only #include this file inside a wrapped*.c file
#endif
#ifndef ADDED_FUNCTIONS
#define ADDED_FUNCTIONS() 
#endif

typedef void* (*pFp_t)(void*);

#define SUPER() ADDED_FUNCTIONS() \
	GO(__tls_get_addr, pFp_t)

#endif // __wrappedldlinuxTYPES_H_

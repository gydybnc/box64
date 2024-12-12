#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "wrappedlibs.h"

#include "wrapper.h"
#include "bridge.h"
#include "librarian/library_private.h"
#include "x64emu.h"

// #include "generated/wrappedmy_librarydefs.h"

const char* my_libraryName = "libgfortran.so.5";
#define LIBNAME libgfortran

// #include "generated/wrappedlibgfortran.h"

#include "wrappercallback.h"

// Insert code here

#include "wrappedlib_init.h"
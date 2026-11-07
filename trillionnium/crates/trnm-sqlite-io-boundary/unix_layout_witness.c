/* Compile-time witness from the actual pinned bundled amalgamation.
 * Never initializes SQLite, opens a database, invokes a VFS, or runs a second
 * SQLite instance. All SQLite API/state in this TU have internal linkage.
 */
#ifndef TRNM_SQLITE_AMALGAMATION
# error "The controlled build must name the pinned dependency amalgamation"
#endif
#ifdef SQLITE_API
# error "Foreign SQLITE_API definition is unsupported"
#endif
#define SQLITE_API static
#include TRNM_SQLITE_AMALGAMATION
/* Let upstream establish feature-test macros before any extra libc header. */
#include <stddef.h>
#include <stdint.h>

#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
# error "Only native Linux x86_64/aarch64 is supported"
#endif
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
# error "Only little-endian target ABI is supported"
#endif
#if !SQLITE_OS_UNIX || OS_VXWORKS || SQLITE_THREADSAFE != 1
# error "Unexpected SQLite OS/threading configuration"
#endif
#if SQLITE_VERSION_NUMBER != 3051003 || SQLITE_ENABLE_LOCKING_STYLE != 0
# error "Unexpected SQLite version or Unix locking configuration"
#endif
#if SQLITE_MAX_MMAP_SIZE != 0x7fff0000 || SQLITE_DEFAULT_MMAP_SIZE != 0
# error "Unexpected bundled mmap layout/configuration"
#endif
#if defined(SQLITE_OMIT_WAL) || defined(SQLITE_SHM_DIRECTORY) \
 || defined(SQLITE_DEBUG) || defined(SQLITE_TEST) \
 || defined(SQLITE_ENABLE_SETLK_TIMEOUT) || defined(SQLITE_4_BYTE_ALIGNED_MALLOC) \
 || defined(SQLITE_MMAP_READWRITE) || defined(SQLITE_ENABLE_BATCH_ATOMIC_WRITE) \
 || defined(SQLITE_DEFAULT_UNIX_VFS) || defined(SQLITE_OMIT_COMPILEOPTION_DIAGS)
# error "Unknown private ABI configuration is unsupported"
#endif

/* These assertions concern real upstream C types, not copied witness structs. */
_Static_assert(sizeof(void *) == 8 && sizeof(int) == 4 && sizeof(unsigned short) == 2,
               "Unsupported LP64 primitive layout");
_Static_assert(_Alignof(void *) == 8 && _Alignof(unixFile) == 8,
               "Unsupported C alignment");

uint64_t trnm_io_witness_layout(int key) {
  switch (key) {
    case 0: return sizeof(void *);
    case 1: return sizeof(int);
    case 2: return sizeof(unsigned short);
    case 3: return _Alignof(void *);
    case 4: return sizeof(sqlite3_file);
    case 5: return sizeof(sqlite3_vfs);
    case 6: return sizeof(sqlite3_io_methods);
    case 7: return sizeof(unixFile);
    case 8: return _Alignof(unixFile);
    case 9: return offsetof(unixFile, pMethod);
    case 10: return offsetof(unixFile, pVfs);
    case 11: return offsetof(unixFile, h);
    case 12: return offsetof(unixFile, pShm);
    case 13: return sizeof(unixShm);
    case 14: return _Alignof(unixShm);
    case 15: return offsetof(unixShm, pShmNode);
    case 16: return sizeof(unixShmNode);
    case 17: return _Alignof(unixShmNode);
    case 18: return offsetof(unixShmNode, hShm);
    default: return UINT64_MAX;
  }
}

const char *trnm_io_witness_compileoption(int index) {
  /* sqlite3_compileoption_get only indexes the static compile-option table. */
  return sqlite3_compileoption_get(index);
}

int trnm_io_witness_version(void) {
  return SQLITE_VERSION_NUMBER;
}

const char *trnm_io_witness_source_id(void) {
  return SQLITE_SOURCE_ID;
}

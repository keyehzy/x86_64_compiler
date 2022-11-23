#include "buffer.h"
#include "types.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <assert.h>

buffer make_buf(u64 capacity)
{
     return (const buffer) {
          .memory = mmap(NULL, capacity, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0),
          .size = 0,
          .capacity = capacity
     };
}

#define declare_buf_append_impl(INT)                            \
     void buf_append_##INT(buffer *buf, INT byte)               \
     {                                                          \
          assert(buf->size + sizeof(byte) <= buf->capacity);    \
          INT *ptr = (INT*)(buf->memory + buf->size);           \
          *ptr = byte;                                          \
          buf->size += sizeof(byte);                            \
     }

declare_buf_append_impl(u8)
declare_buf_append_impl(u16)
declare_buf_append_impl(u32)
declare_buf_append_impl(u64)

declare_buf_append_impl(s8)
declare_buf_append_impl(s16)
declare_buf_append_impl(s32)
declare_buf_append_impl(s64)

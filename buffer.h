#pragma once
#include "types.h"

typedef struct {
     u8 *memory;
     u64 size;
     u64 capacity;
} buffer;

buffer make_buf(u64 capacity);

#define declare_buf_append(INT)                 \
  void buf_append_##INT(buffer *buf, INT byte)  \

declare_buf_append(u8);
declare_buf_append(u16);
declare_buf_append(u32);
declare_buf_append(u64);

declare_buf_append(s8);
declare_buf_append(s16);
declare_buf_append(s32);
declare_buf_append(s64);

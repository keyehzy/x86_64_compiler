#include "test.h"
#include "types.h"
#include "buffer.h"

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

typedef enum {
  RAX = 0,
  RCX,
  RDX,
  RBX,
  RSP,
  RBP,
  RSI,
  RDI,

  // TODO
  R8,
  R9,
  R10,
  R11,
  R12,
  R13,
  R14,
  R15,
} JitRegister;

typedef enum {
     JIT_ADDR_MODE_ZERO_BYTE = 0,
     JIT_ADDR_MODE_ONE_BYTE,
     JIT_ADDR_MODE_FOUR_BYTE,
     JIT_ADDR_MODE_REGISTER,
} JitAddressMode;

typedef enum {
     JIT_REX_W = (4 << 4) + (1 << 3),
     JIT_REX_R = (4 << 4) + (1 << 2),
     JIT_REX_X = (4 << 4) + (1 << 1),
     JIT_REX_B = (4 << 4) + (1 << 0)
} JitREX;

typedef enum {
     JIT_OPERAND_ENCODING_REGISTER,
     JIT_OPERAND_ENCODING_REGISTER_MEMORY,
     JIT_OPERAND_ENCODING_IMMEDIATE,
     JIT_OPERAND_ENCODING_NONE,
} JitOperandEncodingType;

typedef enum {
     JIT_INSTR_EXT_REGISTER,
     JIT_INSTR_EXT_OPCODE,
     JIT_INSTR_EXT_NONE,
} JitInstructionExtensionType;

typedef struct {
     u8 opcode;
     JitInstructionExtensionType extension_type;
     JitOperandEncodingType encoding_type[2];
} JitInstructionEncoding;

const JitInstructionEncoding ret_encoding[] = {
     (JitInstructionEncoding) {
          .opcode = 0xc3,
          .extension_type = JIT_INSTR_EXT_NONE,
          .encoding_type = {
               JIT_OPERAND_ENCODING_NONE,
               JIT_OPERAND_ENCODING_NONE
          }
     }
};

const JitInstructionEncoding push_encoding[] = {
     (JitInstructionEncoding) {
          .opcode = 0x50,
          .extension_type = JIT_INSTR_EXT_NONE,
          .encoding_type = {
               JIT_OPERAND_ENCODING_REGISTER,
               JIT_OPERAND_ENCODING_NONE
          }
     }
};

const JitInstructionEncoding mov_encoding[] = {
     (JitInstructionEncoding) {
          .opcode = 0x89,
          .extension_type = JIT_INSTR_EXT_REGISTER,
          .encoding_type = {
               JIT_OPERAND_ENCODING_REGISTER_MEMORY,
               JIT_OPERAND_ENCODING_REGISTER
          }
     },
     (JitInstructionEncoding) {
          .opcode = 0xc7,
          .extension_type = JIT_INSTR_EXT_OPCODE,
          .encoding_type = {
               JIT_OPERAND_ENCODING_REGISTER_MEMORY,
               JIT_OPERAND_ENCODING_IMMEDIATE
          }
     }
};

const JitInstructionEncoding add_encoding[] = {
     (JitInstructionEncoding) {
          .opcode = 0x01,
          .extension_type = JIT_INSTR_EXT_REGISTER,
          .encoding_type = {
               JIT_OPERAND_ENCODING_REGISTER_MEMORY,
               JIT_OPERAND_ENCODING_REGISTER
          }
     },
     (JitInstructionEncoding) {
          .opcode = 0x81,
          .extension_type = JIT_INSTR_EXT_OPCODE,
          .encoding_type = {
               JIT_OPERAND_ENCODING_REGISTER_MEMORY,
               JIT_OPERAND_ENCODING_IMMEDIATE
          }
     }
};

typedef struct {
     const JitInstructionEncoding *encoding_list;
     u64 encoding_list_length;
} JitMnemonic;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

const JitMnemonic mnemonic_mov = {
     .encoding_list = &mov_encoding[0],
     .encoding_list_length = ARRAY_SIZE(mov_encoding)
};

const JitMnemonic mnemonic_ret = {
     .encoding_list = &ret_encoding[0],
     .encoding_list_length = ARRAY_SIZE(ret_encoding)
};

const JitMnemonic mnemonic_add = {
     .encoding_list = &add_encoding[0],
     .encoding_list_length = ARRAY_SIZE(add_encoding)
};

const JitMnemonic mnemonic_push = {
     .encoding_list = &push_encoding[0],
     .encoding_list_length = ARRAY_SIZE(push_encoding)
};

typedef enum {
     JIT_INSTR_SIZE_8,
     JIT_INSTR_SIZE_16_OR_32,
     JIT_INSTR_SIZE_NONE
} JitInstructionSize;

typedef enum {
     JIT_INSTR_DEST_MEMORY,
     JIT_INSTR_DEST_REGISTER,
     JIT_INSTR_DEST_NONE
} JitInstructionDestination;

typedef enum {
     JIT_OPERAND_NONE,
     JIT_OPERAND_REGISTER,
     JIT_OPERAND_REGISTER_INDIRECT_ACCESS,
     JIT_OPERAND_IMMEDIATE,
} JitOperandType;

typedef struct {
     JitRegister reg;
     JitAddressMode address_mode;
     union {
          u8 one_byte;
          u32 four_byte;
     } displacement;
} JitOperandIndirectAccess;

typedef struct {
     JitOperandType type;
     union {
          JitRegister reg;
          JitOperandIndirectAccess indirect;
          s32 immediate;
     };
} JitOperand;

typedef struct {
     JitMnemonic mnemonic;
     JitInstructionSize instruction_size;
     JitInstructionDestination instruction_dest;
     JitOperand operand[2];
} JitInstruction;

u8 MOD_REG_RM(JitAddressMode mod, JitRegister reg /*src*/, JitRegister rm /*dst*/)
{
     return ((u8)mod << 6) + ((u8)reg << 3) + (u8)rm;
}

bool operand_encoding_typecheck(JitOperand operand, JitOperandEncodingType operand_encoding_type)
{
     switch(operand_encoding_type) {
     case JIT_OPERAND_ENCODING_NONE:
          return operand.type == JIT_OPERAND_NONE;
     case JIT_OPERAND_ENCODING_REGISTER:
          return operand.type == JIT_OPERAND_REGISTER;
     case JIT_OPERAND_ENCODING_REGISTER_MEMORY:
          return operand.type == JIT_OPERAND_REGISTER || operand.type == JIT_OPERAND_REGISTER_INDIRECT_ACCESS;
     case JIT_OPERAND_ENCODING_IMMEDIATE:
          return operand.type == JIT_OPERAND_IMMEDIATE;
     }
     return false;
}

// Encoding: Op1=R/M Op2=reg
void encode_mr(buffer *buf, JitInstruction instruction)
{
     assert((instruction.operand[0].type == JIT_OPERAND_REGISTER) || (instruction.operand[0].type == JIT_OPERAND_REGISTER_INDIRECT_ACCESS));
     assert(instruction.operand[1].type == JIT_OPERAND_REGISTER);

     const JitInstructionEncoding *encoding = NULL;

     for (u64 i = 0; i < instruction.mnemonic.encoding_list_length; i++) {
          JitInstructionEncoding elt = instruction.mnemonic.encoding_list[i]; 
          if(elt.encoding_type[0] == JIT_OPERAND_ENCODING_REGISTER_MEMORY &&
             elt.encoding_type[1] == JIT_OPERAND_ENCODING_REGISTER) {
               encoding = &instruction.mnemonic.encoding_list[i];
               break;
          }
     }

     assert(encoding);

     if (instruction.operand[0].type == JIT_OPERAND_REGISTER)
          buf_append_u8(buf, JIT_REX_W);

     u8 opcode = encoding->opcode;

     switch(instruction.instruction_dest) {
     case JIT_INSTR_DEST_MEMORY:
     case JIT_INSTR_DEST_REGISTER:
          opcode &= ~(1 << 1);
          opcode |= (instruction.instruction_dest << 1);
          break;
     case JIT_INSTR_DEST_NONE:
          break;
     }

     buf_append_u8(buf, opcode);

     if (instruction.operand[0].type == JIT_OPERAND_REGISTER) {
          buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_REGISTER, /*src=*/instruction.operand[1].reg, /*dst=*/instruction.operand[0].reg));
     } else if (instruction.operand[0].type == JIT_OPERAND_REGISTER_INDIRECT_ACCESS) {
          buf_append_u8(buf, MOD_REG_RM(instruction.operand[0].indirect.address_mode, /*src=*/instruction.operand[1].indirect.reg, /*dst=*/instruction.operand[0].reg));
          switch(instruction.operand[0].indirect.address_mode) {
          case JIT_ADDR_MODE_ZERO_BYTE:
               break;
          case JIT_ADDR_MODE_ONE_BYTE:
               buf_append_u8(buf, instruction.operand[0].indirect.displacement.one_byte);
               break;
          case JIT_ADDR_MODE_FOUR_BYTE:
               buf_append_u32(buf, instruction.operand[0].indirect.displacement.four_byte);
               break;
          default:
               assert(false);
               break;
          }
     }
}

// Encoding: Op1=R/M Op2=IMM
void encode_mi(buffer *buf, JitInstruction instruction)
{
     assert((instruction.operand[0].type == JIT_OPERAND_REGISTER) || (instruction.operand[0].type == JIT_OPERAND_REGISTER_INDIRECT_ACCESS));
     assert(instruction.operand[1].type == JIT_OPERAND_IMMEDIATE);

     const JitInstructionEncoding *encoding = NULL;

     for (u64 i = 0; i < instruction.mnemonic.encoding_list_length; i++) {
          JitInstructionEncoding elt = instruction.mnemonic.encoding_list[i]; 
          if(elt.encoding_type[0] == JIT_OPERAND_ENCODING_REGISTER_MEMORY &&
             elt.encoding_type[1] == JIT_OPERAND_ENCODING_IMMEDIATE) {
               encoding = &instruction.mnemonic.encoding_list[i];
               break;
          }
     }

     assert(encoding);

     if (instruction.operand[0].type == JIT_OPERAND_REGISTER)
          buf_append_u8(buf, JIT_REX_W);

     buf_append_u8(buf, encoding->opcode);

     if (instruction.operand[0].type == JIT_OPERAND_REGISTER) {
          buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_REGISTER, /*src=*/0, /*dst=*/instruction.operand[0].reg));
     } else if(instruction.operand[0].type == JIT_OPERAND_REGISTER_INDIRECT_ACCESS) {
          buf_append_u8(buf, MOD_REG_RM(instruction.operand[0].indirect.address_mode, /*src=*/0, /*dst=*/instruction.operand[0].reg));
          switch(instruction.operand[0].indirect.address_mode) {
          case JIT_ADDR_MODE_ZERO_BYTE:
               break;
          case JIT_ADDR_MODE_ONE_BYTE:
               buf_append_u8(buf, instruction.operand[0].indirect.displacement.one_byte);
               break;
          case JIT_ADDR_MODE_FOUR_BYTE:
               buf_append_u32(buf, instruction.operand[0].indirect.displacement.four_byte);
               break;
          default:
               assert(false);
               break;
          }               
     }

     buf_append_s32(buf, instruction.operand[1].immediate);
}

void encode_o(buffer *buf, JitInstruction instruction)
{
     assert(instruction.operand[0].type == JIT_OPERAND_REGISTER);
     assert(instruction.operand[1].type == JIT_OPERAND_NONE);

     const JitInstructionEncoding *encoding = NULL;

     for (u64 i = 0; i < instruction.mnemonic.encoding_list_length; i++) {
          JitInstructionEncoding elt = instruction.mnemonic.encoding_list[i]; 
          if(elt.encoding_type[0] == JIT_OPERAND_ENCODING_REGISTER &&
             elt.encoding_type[1] == JIT_OPERAND_ENCODING_NONE) {
               encoding = &instruction.mnemonic.encoding_list[i];
               break;
          }
     }
     buf_append_u8(buf, encoding->opcode + (u8)instruction.operand[0].reg);
}

void encode_zo(buffer *buf, JitInstruction instruction)
{
     assert(instruction.operand[0].type == JIT_OPERAND_NONE);
     assert(instruction.operand[1].type == JIT_OPERAND_NONE);

     const JitInstructionEncoding *encoding = NULL;

     for (u64 i = 0; i < instruction.mnemonic.encoding_list_length; i++) {
          JitInstructionEncoding elt = instruction.mnemonic.encoding_list[i]; 
          if(elt.encoding_type[0] == JIT_OPERAND_ENCODING_NONE &&
             elt.encoding_type[1] == JIT_OPERAND_ENCODING_NONE) {
               encoding = &instruction.mnemonic.encoding_list[i];
               break;
          }
     }
     buf_append_u8(buf, encoding->opcode);
}

void encode(buffer *buf, JitInstruction instruction)
{
     switch(instruction.operand[0].type) {
     case JIT_OPERAND_REGISTER:
          switch(instruction.operand[1].type) {
          case JIT_OPERAND_REGISTER:
               return encode_mr(buf, instruction);
          case JIT_OPERAND_REGISTER_INDIRECT_ACCESS:
               return encode_mr(buf, instruction); // actually rm
          case JIT_OPERAND_IMMEDIATE:
               return encode_mi(buf, instruction);
          case JIT_OPERAND_NONE:
               return encode_o(buf, instruction);
          default:
               assert(false);
          }
     case JIT_OPERAND_REGISTER_INDIRECT_ACCESS:
          switch(instruction.operand[1].type) {
          case JIT_OPERAND_REGISTER:
               return encode_mr(buf, instruction);
          case JIT_OPERAND_IMMEDIATE:
               return encode_mi(buf, instruction);
          default:
               assert(false);
          }
     case JIT_OPERAND_IMMEDIATE:
          assert(false);
     case JIT_OPERAND_NONE:
          switch(instruction.operand[1].type) {
          case JIT_OPERAND_NONE:
               return encode_zo(buf, instruction);
          default:
               assert(false);
          }
     }
}

JitOperand operand_none()
{
     return (JitOperand) {.type = JIT_OPERAND_NONE };
}

JitOperand operand_register(JitRegister reg)
{
     return (JitOperand) {.type = JIT_OPERAND_REGISTER, .reg = reg};
}

JitOperand operand_immediate(s32 value)
{
     return (JitOperand) {.type = JIT_OPERAND_IMMEDIATE, .immediate = value};
}

JitOperand operand_indirect_access(JitRegister reg, u8 offset)
{
     return (JitOperand) {
          .type = JIT_OPERAND_REGISTER_INDIRECT_ACCESS,
          .indirect = (JitOperandIndirectAccess) {
               .reg = reg,
               .address_mode = JIT_ADDR_MODE_ONE_BYTE, // four byte etc...
               .displacement = { offset }
          }
     };
}

void buf_append_push_reg(buffer *buf, JitRegister reg)
{
     encode(buf, (JitInstruction) {
               .mnemonic = mnemonic_push,
               .operand = { operand_register(reg), operand_none() }
          });
     // buf_append_u8(buf, 0x50 + (u8)reg);
}

void buf_append_pop_reg(buffer *buf, JitRegister reg)
{
     buf_append_u8(buf, 0x58 + (u8)reg);
}



void buf_append_mov_reg_imm32(buffer *buf, JitRegister reg, s32 value)
{
     encode(buf, (JitInstruction) {
               .mnemonic = mnemonic_mov,
               .instruction_size = JIT_INSTR_SIZE_16_OR_32,
               .instruction_dest = JIT_INSTR_DEST_NONE,
               .operand = { operand_register(reg), operand_immediate(value) }
          });

     // buf_append_u8(buf, JIT_REX_W);
     // buf_append_u8(buf, 0xc7);
     // buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_REGISTER, 0, reg));
     // buf_append_s32(buf, value);
}

void buf_append_mov_reg_reg(buffer *buf, JitRegister dst, JitRegister src)
{
     encode(buf, (JitInstruction) {
               .mnemonic = mnemonic_mov,
               .instruction_size = JIT_INSTR_SIZE_16_OR_32,
               .instruction_dest = JIT_INSTR_DEST_MEMORY,
               .operand = { operand_register(dst), operand_register(src) }
          });
     // buf_append_u8(buf, JIT_REX_W);
     // buf_append_u8(buf, 0x89);
     // buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_REGISTER, src, dst));
}

void buf_append_mov_rm_reg(buffer *buf, JitRegister dst, JitRegister src, u8 displacement)
{
     encode(buf, (JitInstruction) {
               .mnemonic = mnemonic_mov,
               .instruction_size = JIT_INSTR_SIZE_16_OR_32,
               .instruction_dest = JIT_INSTR_DEST_MEMORY,
               .operand = { operand_indirect_access(dst, displacement), operand_register(src) }
          });
     /* buf_append_u8(buf, 0x89); */
     /* buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_ONE_BYTE, src, dst)); */
     /* buf_append_u8(buf, displacement); */
}

void buf_append_mov_reg_rm(buffer *buf, JitRegister dst, JitRegister src, u8 displacement)
{
     encode(buf, (JitInstruction) { // actually rm
               .mnemonic = mnemonic_mov,
               .instruction_size = JIT_INSTR_SIZE_16_OR_32,
               .instruction_dest = JIT_INSTR_DEST_REGISTER,
               .operand = { operand_indirect_access(src, displacement), operand_register(dst) }
          });
     // buf_append_u8(buf, JIT_REX_W);
     // buf_append_u8(buf, 0x8b);
     // buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_ONE_BYTE, dst, src));
     // buf_append_u8(buf, displacement);
}

void buf_append_mov_rm_imm32(buffer *buf, JitRegister reg, u8 displacement, s32 value)
{
     encode(buf, (JitInstruction) {
               .mnemonic = mnemonic_mov,
               .instruction_size = JIT_INSTR_SIZE_16_OR_32,
               .instruction_dest = JIT_INSTR_DEST_NONE,
              .operand = { operand_indirect_access(reg, displacement), operand_immediate(value) }
          });

     // buf_append_u8(buf, 0xc7);
     // buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_ONE_BYTE, 0, reg));
     // buf_append_u8(buf, displacement);
     // buf_append_s32(buf, value);
}

void buf_append_add_reg_reg(buffer *buf, JitRegister dst, JitRegister src)
{
     encode(buf, (JitInstruction) {
               .mnemonic = mnemonic_add,
               .instruction_size = JIT_INSTR_SIZE_16_OR_32,
               .instruction_dest = JIT_INSTR_DEST_MEMORY,
               .operand = { operand_register(dst), operand_register(src) }
          });
     // buf_append_u8(buf, JIT_REX_W);
     // buf_append_u8(buf, 0x01);
     // buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_REGISTER, src, dst));
}

void buf_append_add_reg_imm32(buffer *buf, JitRegister reg, s32 value)
{
     encode(buf, (JitInstruction) {
               .mnemonic = mnemonic_add,
               .instruction_size = JIT_INSTR_SIZE_16_OR_32,
               .instruction_dest = JIT_INSTR_DEST_NONE,
               .operand = { operand_register(reg), operand_immediate(value) }
          });
     // buf_append_u8(buf, JIT_REX_W);
     // buf_append_u8(buf, 0x81);
     // buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_REGISTER, 0, reg));
     // buf_append_s32(buf, value);
}

void buf_append_add_reg_rm(buffer *buf, JitRegister dst, JitRegister src, u8 displacement)
{
     encode(buf, (JitInstruction) { // actually rm
               .mnemonic = mnemonic_add,
               .instruction_size = JIT_INSTR_SIZE_16_OR_32,
               .instruction_dest = JIT_INSTR_DEST_REGISTER,
               .operand = { operand_indirect_access(src, displacement), operand_register(dst) }
          });

     // buf_append_u8(buf, JIT_REX_W);
     // buf_append_u8(buf, 0x03);
     // buf_append_u8(buf, MOD_REG_RM(JIT_ADDR_MODE_ONE_BYTE, dst, src));
     // buf_append_u8(buf, displacement);
}

typedef int (*JitConstantInt)();
JitConstantInt make_constant_int(int value)
{
     buffer buf = make_buf(4096);
     buf_append_push_reg(&buf, RBP);
     buf_append_mov_reg_reg(&buf, RBP, RSP);

     buf_append_mov_rm_reg(&buf, RBP, RDI, -4);
     buf_append_mov_reg_imm32(&buf, RAX, value);

     buf_append_pop_reg(&buf, RBP);

     encode(&buf, (JitInstruction) { 
               .mnemonic = mnemonic_ret,
               .instruction_size = JIT_INSTR_SIZE_NONE,
               .instruction_dest = JIT_INSTR_DEST_NONE,
               .operand = {{0}}
          });
     return (JitConstantInt)buf.memory;
}

typedef int (*JitIdentityInt)();
JitIdentityInt make_identity_int()
{
     buffer buf = make_buf(4096);
     buf_append_push_reg(&buf, RBP);
     buf_append_mov_reg_reg(&buf, RBP, RSP);

     buf_append_mov_rm_reg(&buf, RBP, RDI, -4);
     buf_append_mov_reg_rm(&buf, RAX, RBP, -4);

     buf_append_pop_reg(&buf, RBP);
     encode(&buf, (JitInstruction) { 
               .mnemonic = mnemonic_ret,
               .instruction_size = JIT_INSTR_SIZE_NONE,
               .instruction_dest = JIT_INSTR_DEST_NONE, 
               .operand = {{0}}
          });
     return (JitIdentityInt)buf.memory;
}

typedef int (*JitIncrementInt)();
JitIncrementInt make_increment_int(s32 value)
{
     buffer buf = make_buf(4096);
     buf_append_push_reg(&buf, RBP);
     buf_append_mov_reg_reg(&buf, RBP, RSP);

     buf_append_mov_rm_reg(&buf, RBP, RDI, -20);
     buf_append_mov_rm_imm32(&buf, RBP, -4, value);
     buf_append_mov_reg_rm(&buf, RDX, RBP, -20);
     buf_append_mov_reg_rm(&buf, RAX, RBP, -4);
     buf_append_add_reg_reg(&buf, RAX, RDX);

     /* buf_append_mov_rm_reg(&buf, RBP, RDI, -4); */
     /* buf_append_mov_reg_imm32(&buf, RAX, value); */
     /* buf_append_add_reg_rm(&buf, RAX, RBP, -4); */

     buf_append_pop_reg(&buf, RBP);
     encode(&buf, (JitInstruction) { 
               .mnemonic = mnemonic_ret,
               .instruction_size = JIT_INSTR_SIZE_NONE,
               .instruction_dest = JIT_INSTR_DEST_NONE, 
               .operand = {{0}}
          });
     return (JitIdentityInt)buf.memory;
}

typedef int (*JitAddInt)();
JitIncrementInt make_add2_int(s32 value1, s32 value2)
{
     buffer buf = make_buf(4096);
     buf_append_push_reg(&buf, RBP);
     buf_append_mov_reg_reg(&buf, RBP, RSP);

     buf_append_mov_rm_imm32(&buf, RBP, -4, value1);
     buf_append_mov_reg_imm32(&buf, RAX, value2);
     buf_append_add_reg_rm(&buf, RAX, RBP, -4);

     buf_append_pop_reg(&buf, RBP);
     encode(&buf, (JitInstruction) { 
               .mnemonic = mnemonic_ret,
               .instruction_size = JIT_INSTR_SIZE_NONE,
               .instruction_dest = JIT_INSTR_DEST_NONE, 
               .operand = {{0}}
          });
     return (JitIdentityInt)buf.memory;
}

void spec()
{
     test_array suite = ta_init();

     it("should create a function that returns 42",
        JitConstantInt result = make_constant_int(42);
        ASSERT_EQ(result(), 42);
     );

     it("should create a function that fails for different values",
        JitConstantInt result = make_constant_int(42);
        ASSERT_NEQ(result(), 13);
     );

     it("should create a function that returns the value passed",
        JitIdentityInt result = make_identity_int();
        ASSERT_EQ(result(42), 42);
     );

     it("should create a function that increment the value passed by 2",
        JitIncrementInt result = make_increment_int(2);
        ASSERT_EQ(result(42), 44);
     );

     it("should create a function that adds two integers",
        JitIncrementInt result = make_add2_int(42, 43);
        ASSERT_EQ(result(), 85);
     );

     verify(suite);
}

int main(int argc, char **argv)
{
     spec();
     return 0;
}


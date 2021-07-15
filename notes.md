# JIT VM rev + pwn

## VM language

- Explicit functions (that are JITed) with explicit argument counts
- Stack-based VM (similar to wasm/JVM) with pre-declared local count for each
  function (e.g. `loadLocal <n>` op)
- Jumps / branches are to labels only (labels are present in bytecode)
- Functions are referenced by index (function table in bytecode)
- Independently-addressed constant and data sections (e.g. `loadConst32
  <offset>`, `storeData8 <offset>`)
- No system/host functions
- 2 memory regions: rodata and data
- Last value pushed before call is first argument

## JIT implementation

- Lazy compilation of functions via pseudo-GOT/PLT with stubs to trigger
  compilation (calls via PLT stub)
- All locals and stack values go on stack
- Epilogue at return site pops return value and places it in argument slots -
  essentially, transparently reading from/writing to the stack of the callee
- Callee handles moving stack pointer before call to reserve space for returns
  or after call to remove space from arguments
- Stack layout:
```
[...]
[arg 1]
[arg 0]
[return addr]
[saved RBP] <- RBP
[local 0]
[local 1]
[...]
[VM stack]
[VM stack] <- RSP
```
```
[...]
[arg 1/ret 0]
[arg 0]
[return addr]
[...]
```
```
[...]
[arg 0/ret 1]
[ret 0]
[return addr]
[...]
```
- R15 holds pointer to VM context, not touched by any JIT-generated code
- R14 and R13 are pointers to rodata and data segments
- JIT locks down 2^31 memory region at startup for code (so 32 bit relative
  offsets can be used)


## Exploitation

- Locals aren't cleared at entry into a function, so saved register values
  previously placed on the stack (by the JIT compiler calling convention
  translation) can be read to get addresses of the 2 memory segments and address
  of the shared object
- Stack checker ignores branches/jumps, allowing underflow of the stack pointer
  to overwrite return addresses / base pointer
- ROP to mprotect gadget and then jump to shellcode

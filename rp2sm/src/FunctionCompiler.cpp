#include "FunctionCompiler.hpp"
#include "support.hpp"

#include "challenge.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <type_traits>

#include <sys/mman.h>

namespace rp2sm {

struct OpcodeInfo {
	uint8_t code;
	uint8_t imm_len;
	arg_idx_t n_args;
	arg_idx_t n_ret;

	constexpr OpcodeInfo(uint8_t code, uint8_t imm_len, arg_idx_t n_args, arg_idx_t n_ret) :
		code(code), imm_len(imm_len), n_args(n_args), n_ret(n_ret)
	{}
};

struct OpcodeTableEntry {
	const bool is_valid;
	const OpcodeInfo info;

	using compile_func_t = void(FunctionCompiler& compiler, uint8_t code);

	compile_func_t* const compile;

	constexpr OpcodeTableEntry() :
		is_valid(0), info(0, 0, 0, 0), compile(nullptr)
	{}
	constexpr OpcodeTableEntry(
		uint8_t code,
		uint8_t imm_len,
		arg_idx_t n_args,
		arg_idx_t n_ret,
		compile_func_t* const compile
	) :
		is_valid(1), info(code, imm_len, n_args, n_ret),
		compile(compile)
	{}
};


namespace {

// TODO(chall): consider noinline (+ dedupe)
void write_reloc(void* reloc_addr, void* target) {
	// reloc_addr points to rel32 for rip-relative addr in last bytes of
	// instruction (i.e. `rip` is reloc_addr + 4)
	auto offset =
		reinterpret_cast<uint8_t*>(target) -
		(reinterpret_cast<uint8_t*>(reloc_addr) + 4);
	static_assert(std::is_same_v<decltype(offset), std::ptrdiff_t>);
	*reinterpret_cast<int32_t*>(reloc_addr) = checked_narrow<int32_t>(offset);
}

void cc_write_reloc_now(FunctionCompiler& cc, void* target) {
	write_reloc(cc.curr_asm_addr, target);
	cc.curr_asm_addr = reinterpret_cast<uint8_t*>(cc.curr_asm_addr) + 4;
}

constexpr int32_t arg_slot_idx_to_disp32(uint8_t slot_idx) {
	// argument slots are 8 bytes wide because stack slots are also 8 bytes
	// wide (so `push`/`pop` could be used)
	return (slot_idx * sizeof(size_t)) + 0x10; // 16 bytes for saved rbp, ret addr
}

constexpr uint8_t arg_idx_to_slot_idx(uint8_t arg_idx, const FunctionInfo& func) {
	uint8_t n_slots = std::max(func.n_args, func.n_ret);
	return n_slots - (func.n_args - arg_idx);
}

constexpr int32_t local_idx_to_disp32(local_idx_t local_idx) {
	return -((local_idx + 1) * sizeof(int32_t)); // first slot is 1 slot below saved rbp
}


// V(NAME, CODE, IMM_LEN, ARGS, RET, FUNCNAME)
#define OPCODES(V) \
	V(NOP,  0x00, 0, 0, 0, nop) \
	V(DROP, 0x01, 0, 1, 0, drop) \
	V(DUP,  0x02, 0, 1, 2, dup) \
	\
	V(IMMW, 0x08, 4, 0, 1, immw) \
	V(IMMH, 0x09, 2, 0, 1, immh) \
	V(IMMB, 0x0a, 1, 0, 1, immb) \
	\
	V(CALL,  0x10, sizeof(func_index_t), 0, 0, call) /* variable args/ret */ \
	V(RET,   0x11, 0, 0, 0, ret) /* variable args */ \
	V(LABEL, 0x12, 0, 0, 0, label) /* labels and branches intentially wrong for validator bug + pwn */ \
	V(BR,    0x13, sizeof(label_idx_t), 0, 0, br) \
	V(BR_IF, 0x14, sizeof(label_idx_t), 1, 0, br_if) \
	\
	V(LOCAL_GET, 0x20, sizeof(local_idx_t), 0, 1, local_get) \
	V(LOCAL_SET, 0x21, sizeof(local_idx_t), 1, 0, local_set) \
	V(LOCAL_TEE, 0x22, sizeof(local_idx_t), 1, 1, local_tee) \
	V(ARG_GET,   0x23, sizeof(arg_idx_t),   0, 1, arg_get) \
	\
	V(MEM_LW,    0x30, 0, 1, 1, mem_ldw) \
	V(MEM_LH,    0x31, 0, 1, 1, mem_ldx) \
	V(MEM_LB,    0x32, 0, 1, 1, mem_ldx) \
	V(MEM_LHU,   0x33, 0, 1, 1, mem_ldx) \
	V(MEM_LBU,   0x34, 0, 1, 1, mem_ldx) \
	V(MEM_SW,    0x35, 0, 2, 0, mem_st) \
	V(MEM_SH,    0x36, 0, 2, 0, mem_st) \
	V(MEM_SB,    0x37, 0, 2, 0, mem_st) \
	V(CONST_LW,  0x38, 0, 1, 1, const_ldw) \
	V(CONST_LH,  0x39, 0, 1, 1, const_ldx) \
	V(CONST_LB,  0x3a, 0, 1, 1, const_ldx) \
	V(CONST_LHU, 0x3b, 0, 1, 1, const_ldx) \
	V(CONST_LBU, 0x3c, 0, 1, 1, const_ldx) \
	\
	V(EQZ, 0x40, 0, 1, 1, test_un) \
	V(NEZ, 0x41, 0, 1, 1, test_un) \
	V(EQ,  0x42, 0, 2, 1, test) \
	V(NE,  0x43, 0, 2, 1, test) \
	V(LT,  0x44, 0, 2, 1, test) \
	V(GT,  0x45, 0, 2, 1, test) \
	V(LE,  0x46, 0, 2, 1, test) \
	V(GE,  0x47, 0, 2, 1, test) \
	V(LTU, 0x48, 0, 2, 1, test) \
	V(GTU, 0x49, 0, 2, 1, test) \
	V(LEU, 0x4a, 0, 2, 1, test) \
	V(GEU, 0x4b, 0, 2, 1, test) \
	\
	V(AND, 0x50, 0, 2, 1, binop) \
	V(OR,  0x51, 0, 2, 1, binop) \
	V(XOR, 0x52, 0, 2, 1, binop) \
	V(ADD, 0x53, 0, 2, 1, binop) \
	V(SUB, 0x54, 0, 2, 1, binop) \
	V(SHL, 0x5c, 0, 2, 1, binop_shift) \
	V(SHR, 0x5d, 0, 2, 1, binop_shift) \
	V(SAR, 0x5e, 0, 2, 1, binop_shift) \
// #define OPCODES



#define DEF_OP(NAME, CODE, IMM_LEN, ARGS, RET, FUNCNAME) \
	[[maybe_unused]] constexpr auto OP_##NAME = OpcodeInfo{CODE, IMM_LEN, ARGS, RET};

OPCODES(DEF_OP);


#define DEF_OP_COMPILE_FUNC(name) \
	void compile_op_ ## name([[maybe_unused]] FunctionCompiler& cc, [[maybe_unused]] uint8_t opcode)

DEF_OP_COMPILE_FUNC(nop) {
	// nop
}

DEF_OP_COMPILE_FUNC(drop) {
	// add rsp, 8
	cc.append_code_frag(unhexlify("4883c408"));
}

DEF_OP_COMPILE_FUNC(dup) {
	// mov eax, dword [rsp]; push rax;
	cc.append_code_frag(unhexlify("8b042450"));
}


DEF_OP_COMPILE_FUNC(immw) {
	auto imm = cc.bytecode_read_imm<int32_t>();
	cc.append_code_frag(unhexlify("68")); // push imm32
	cc.append_code_imm(imm); // imm32
}

DEF_OP_COMPILE_FUNC(immh) {
	auto imm = cc.bytecode_read_imm<int16_t>();
	cc.append_code_frag(unhexlify("68")); // push imm32
	cc.append_code_imm<int32_t>(imm); // imm32
}

DEF_OP_COMPILE_FUNC(immb) {
	auto imm = cc.bytecode_read_imm<int8_t>();
	cc.append_code_frag(unhexlify("6a")); // push imm8
	cc.append_code_imm(imm); // imm8
}


DEF_OP_COMPILE_FUNC(call) {
	auto target_idx = cc.bytecode_read_imm<func_index_t>();
	if (target_idx >= cc.st.functions.size()) {
		std::abort();
	}

	const auto& target = cc.st.functions[target_idx];
	if (cc.stack_height < target.n_args) {
		std::abort();
	}

	auto n_slots = std::max(target.n_args, target.n_ret);
	static_assert(std::is_same_v<decltype(n_slots), uint8_t>);

	if (target.n_args != n_slots) {
		cc.append_code_frag(unhexlify("4881ec")); // sub rsp, imm32
		 // imm32 (no overflow possible)
		cc.append_code_imm<int32_t>((n_slots - target.n_args) * sizeof(size_t));
	}

	cc.append_code_frag(unhexlify("e8")); // call rel32
	cc_write_reloc_now(cc, cc.st.pltstubs[cc.st.get_idx_for_func(target_idx)]); // rel32

	if (target.n_ret != n_slots) {
		cc.append_code_frag(unhexlify("4881c4")); // add rsp, imm32
		// imm32 (no overflow possible)
		cc.append_code_imm<int32_t>((n_slots - target.n_ret) * sizeof(size_t));
	}

	cc.stack_height += static_cast<int>(target.n_ret) - target.n_args;
}

DEF_OP_COMPILE_FUNC(ret) {
	if (cc.stack_height < cc.func.n_ret) {
		std::abort();
	}

	cc.append_code_frag(unhexlify("e9")); // jmp rel32
	auto reloc_loc = cc.curr_asm_addr;
	cc.append_code_imm<int32_t>(0); // rel32(fixup)
	cc.ret_relocs.push_back(reloc_loc);
	cc.is_dead = true;
}


CHALL_NOINLINE
void cc_scan_flush_relocs(FunctionCompiler& cc, label_idx_t target) {
	for (auto it = cc.pending_relocs.begin(); it != cc.pending_relocs.end(); it++) {
		const auto& reloc = *it;
		if (reloc.target == target) {
			write_reloc(reloc.addr, cc.curr_asm_addr);
			it = cc.pending_relocs.erase(it);
		}
	}
}

CHALL_NOINLINE
void cc_add_reloc(FunctionCompiler& cc, void* addr, label_idx_t target) {
	// TODO: consider just inlining?
	cc.pending_relocs.push_back(FunctionCompiler::Relocation{
		.addr = addr,
		.target = target,
	});
}

// writes rel32 relocation, queueing if necessary
void cc_write_or_add_reloc(FunctionCompiler& cc, label_idx_t target) {
	if (target < cc.labels.size()) {
		// We've resolved the label already
		cc_write_reloc_now(cc, cc.labels[target]);
	} else {
		// Need to add it to pending list
		auto addr = cc.curr_asm_addr;
		cc.append_code_imm<int32_t>(0); // rel32(fixup)
		cc_add_reloc(cc, addr, target);
	}
}

DEF_OP_COMPILE_FUNC(label) {
	auto idx = checked_narrow<label_idx_t>(cc.labels.size());

	cc.labels.push_back(cc.curr_asm_addr);

	// Fixup all pending relocations referring to this label
	cc_scan_flush_relocs(cc, idx);

	cc.is_dead = false;
}

DEF_OP_COMPILE_FUNC(br) {
	auto label_idx = cc.bytecode_read_imm<label_idx_t>();

	cc.append_code_frag(unhexlify("e9")); // jmp rel32
	cc_write_or_add_reloc(cc, label_idx); // rel32

	cc.is_dead = true;
}

DEF_OP_COMPILE_FUNC(br_if) {
	auto label_idx = cc.bytecode_read_imm<label_idx_t>();

	// pop rax; test eax, eax; jnz rel32;
	cc.append_code_frag(unhexlify("5885c00f85"));
	cc_write_or_add_reloc(cc, label_idx); // rel32
}


local_idx_t cc_checked_get_local_idx(const FunctionCompiler& cc) {
	auto local_idx = cc.bytecode_read_imm<local_idx_t>();
	if (local_idx >= cc.func.n_locals) {
		std::abort();
	}
	return local_idx;
}

DEF_OP_COMPILE_FUNC(local_get) {
	auto local_idx = cc_checked_get_local_idx(cc);
	cc.append_code_frag(unhexlify("8b85")); // mov eax, dword [rbp+disp32]
	cc.append_code_imm(local_idx_to_disp32(local_idx)); // disp32
	cc.append_code_frag(unhexlify("50")); // push rax
}

DEF_OP_COMPILE_FUNC(local_set) {
	auto local_idx = cc_checked_get_local_idx(cc);
	cc.append_code_frag(unhexlify("588985")); // pop rax; mov dword [rbp+disp32], eax;
	cc.append_code_imm(local_idx_to_disp32(local_idx)); // disp32
}

DEF_OP_COMPILE_FUNC(local_tee) {
	auto local_idx = cc_checked_get_local_idx(cc);
	// mov eax, dword [rsp]; mov dword [rbp+disp32], eax;
	cc.append_code_frag(unhexlify("8b04248985"));
	cc.append_code_imm(local_idx_to_disp32(local_idx)); // disp32
}

DEF_OP_COMPILE_FUNC(arg_get) {
	auto arg_idx = cc.bytecode_read_imm<arg_idx_t>();
	if (arg_idx >= cc.func.n_args) {
		std::abort();
	}
	int32_t displ = arg_slot_idx_to_disp32(arg_idx_to_slot_idx(arg_idx, cc.func));
	cc.append_code_frag(unhexlify("8b85")); // mov eax, dword [rbp+disp32]
	cc.append_code_imm(displ); // disp32
	cc.append_code_frag(unhexlify("50")); // push rax
}


DEF_OP_COMPILE_FUNC(mem_ldw) {
	// pop rsi; mov eax, dword [rsi+r13]; push rax;
	cc.append_code_frag(unhexlify("5e428b042e50"));
}

DEF_OP_COMPILE_FUNC(mem_ldx) {
	// pop rsi; movsx eax, word [rsi+r13]; push rax;
	constexpr auto _code = unhexlify("5e420fbf042e50");
	constexpr std::size_t prim_op_idx = 3;
	static_assert(_code[prim_op_idx] == 0xbf); // movsxw primary opcode
	auto code = _code;

	switch (opcode) {
	case OP_MEM_LH.code:
		// default is movsxw
		break;
	case OP_MEM_LB.code:
		code[prim_op_idx] = 0xbe; // movsxb
		break;
	case OP_MEM_LHU.code:
		code[prim_op_idx] = 0xb7; // movzxw
		break;
	case OP_MEM_LBU.code:
		code[prim_op_idx] = 0xb6; // movzxw
		break;
	default:
		std::abort();
	}
	cc.append_code_frag(code);
}

DEF_OP_COMPILE_FUNC(mem_st) {
	// upfront opcode check since clang can't reorder the check in this function,
	// as we're performing memory writes before executing the check
	switch (opcode) {
	case OP_MEM_SW.code:
	case OP_MEM_SH.code:
	case OP_MEM_SB.code:
		break;
	default:
		std::abort();
	}

	cc.append_code_frag(unhexlify("5f58")); // pop rdi; pop rax;
	if (opcode == OP_MEM_SH.code) {
		// need operand size override prefix first
		cc.append_code_frag(unhexlify("66"));
	}
	cc.append_code_frag(unhexlify("42")); // REX.X for ModR/M bit
	switch (opcode) {
	case OP_MEM_SW.code:
	case OP_MEM_SH.code:
		// movw/movd are differentiated by op sz prefix, assembled previously
		cc.append_code_frag(unhexlify("89"));
		break;
	case OP_MEM_SB.code:
		// movb primary opcode
		cc.append_code_frag(unhexlify("88"));
		break;
	}
	cc.append_code_frag(unhexlify("042f")); // (mov modr/m+sib) [rdi+r13], (e)a(x|l)
}

DEF_OP_COMPILE_FUNC(const_ldw) {
	// pop rsi; mov eax, dword [rsi+r14]; push rax;
	cc.append_code_frag(unhexlify("5e428b043650"));
}

DEF_OP_COMPILE_FUNC(const_ldx) {
	// TODO: somehow deduplicate?
	// pop rsi; movsx eax, word [rsi+r14]; push rax;
	constexpr auto _code = unhexlify("5e420fbf043650");
	constexpr std::size_t prim_op_idx = 3;
	static_assert(_code[prim_op_idx] == 0xbf); // movsxw primary opcode
	auto code = _code;

	switch (opcode) {
	case OP_CONST_LH.code:
		// default is movsxw
		break;
	case OP_CONST_LB.code:
		code[prim_op_idx] = 0xbe; // movsxb
		break;
	case OP_CONST_LHU.code:
		code[prim_op_idx] = 0xb7; // movzxw
		break;
	case OP_CONST_LBU.code:
		code[prim_op_idx] = 0xb6; // movzxw
		break;
	default:
		std::abort();
	}
	cc.append_code_frag(code);
}


DEF_OP_COMPILE_FUNC(test_un) {
	// pop rdx; xor eax, eax; test edx, edx; setz al; push rax;
	constexpr auto _code = unhexlify("5a31c085d20f94c050");
	constexpr std::size_t prim_op_idx = 6;
	static_assert(_code[prim_op_idx] == 0x94); // setz primary opcode
	auto code = _code;

	switch (opcode) {
	case OP_EQZ.code:
		// default is setz
		break;
	case OP_NEZ.code:
		code[prim_op_idx] = 0x95; // setnz
		break;
	default:
		std::abort();
	}
	cc.append_code_frag(code);
}

DEF_OP_COMPILE_FUNC(test) {
	// first arg is rhs, second arg is lhs

	// pop rdx; pop rcx; xor eax, eax; cmp ecx, edx; sete al; push rax;
	constexpr auto _code = unhexlify("5a5931c039d10f94c050");
	constexpr std::size_t prim_op_idx = 7;
	static_assert(_code[prim_op_idx] == 0x94); // sete primary opcode
	auto code = _code;

	switch (opcode) {
	case OP_EQ.code:
		// default is sete
		break;
	case OP_NE.code:
		code[prim_op_idx] = 0x95; // setne
		break;
	case OP_LT.code:
		code[prim_op_idx] = 0x9c; // setl
		break;
	case OP_GT.code:
		code[prim_op_idx] = 0x9f; // setg
		break;
	case OP_LE.code:
		code[prim_op_idx] = 0x9e; // setle
		break;
	case OP_GE.code:
		code[prim_op_idx] = 0x9d; // setge
		break;
	case OP_LTU.code:
		code[prim_op_idx] = 0x92; // setb
		break;
	case OP_GTU.code:
		code[prim_op_idx] = 0x97; // seta
		break;
	case OP_LEU.code:
		code[prim_op_idx] = 0x96; // setbe
		break;
	case OP_GEU.code:
		code[prim_op_idx] = 0x93; // setae
		break;
	default:
		std::abort();
	}
	cc.append_code_frag(code);
}

DEF_OP_COMPILE_FUNC(binop) {
	// first arg is rhs, second arg is lhs

	// pop rdx; pop rax; add eax, edx; push rax;
	constexpr auto _code = unhexlify("5a5801d050");
	constexpr std::size_t prim_op_idx = 2;
	static_assert(_code[prim_op_idx] == 0x01); // add primary opcode
	auto code = _code;

	switch (opcode) {
	case OP_ADD.code:
		// default is add
		break;
	case OP_OR.code:
		code[prim_op_idx] = 0x09; // or
		break;
	case OP_AND.code:
		code[prim_op_idx] = 0x21; // and
		break;
	case OP_SUB.code:
		code[prim_op_idx] = 0x29; // sub
		break;
	case OP_XOR.code:
		code[prim_op_idx] = 0x31; // xor
		break;
	default:
		std::abort();
	}
	cc.append_code_frag(code);
}

DEF_OP_COMPILE_FUNC(binop_shift) {
	// first arg is amount, second arg is operand

	// pop rcx; pop rax; shl rax, cl; push rax;
	constexpr auto _code = unhexlify("595848d3e050");
	constexpr std::size_t modrm_idx = 4;
	static_assert(_code[modrm_idx] == 0xe0); // modrm byte
	auto code = _code;

	switch (opcode) {
	case OP_SHL.code:
		// default is shl rax
		break;
	case OP_SHR.code:
		code[modrm_idx] = 0xe8; // shr rax
		break;
	case OP_SAR.code:
		code[modrm_idx] = 0xf8; // shr rax
		break;
	default:
		std::abort();
	}
	cc.append_code_frag(code);
}



constinit OpcodeTableEntry table[0x100] = {
#define DEF_TABLE_ENTRY(NAME, CODE, IMM_LEN, ARGS, RET, FUNCNAME) \
	[CODE] = {CODE, IMM_LEN, ARGS, RET, compile_op_ ## FUNCNAME},
	OPCODES(DEF_TABLE_ENTRY)
#undef DEF_TABLE_ENTRY
};

} // namespace


CHALL_NOINLINE
void FunctionCompiler::scan_and_compile_op() {
	auto opcode = *reinterpret_cast<uint8_t*>(curr_bytecode_addr);
	if (opcode == OP_LABEL.code) {
		is_dead = false;
	}

	auto entry = table[opcode];
	if (!entry.is_valid) {
		std::abort();
	}

	if (get_curr_bytecode_buf_offs() + 1 + entry.info.imm_len > func.len) {
		std::abort();
	}
	if (!is_dead && stack_height < entry.info.n_args) {
		std::abort();
	}

	curr_bytecode_addr = reinterpret_cast<uint8_t*>(curr_bytecode_addr) + 1;
	if (!is_dead) {
		entry.compile(*this, opcode);
	}
	curr_bytecode_addr = reinterpret_cast<uint8_t*>(curr_bytecode_addr) + entry.info.imm_len;

	// TODO(chall): consider not checking here for easier pwn?
	if (!is_dead) {
		stack_height += static_cast<int>(entry.info.n_ret) - entry.info.n_args;
	}
}

namespace {

CHALL_NOINLINE
void write_retval_mover(FunctionCompiler& cc) {
	auto n_stackslots = std::max(cc.func.n_ret, cc.func.n_args);
	uint8_t slot_idx = n_stackslots - cc.func.n_ret;
	for (auto i = 0; i < cc.func.n_ret; i++, slot_idx++) {
		int32_t offs = arg_slot_idx_to_disp32(slot_idx);
		cc.append_code_frag(unhexlify("58488985")); // pop rax; mov qword [rbp+disp32], rax;
		cc.append_code_imm(offs); // disp32
	}
}

} // namespace

void* FunctionCompiler::compile() {
	auto& seg_code = st.seg_code;
	auto func_addr = seg_code.top;
	curr_asm_addr = func_addr;
	curr_bytecode_addr = func.code_buf;
	seg_code.seg.set_prot(PROT_READ | PROT_WRITE);

	// push rbp; mov rbp, rsp;
	append_code_frag(unhexlify("554889e5"));
	if (func.n_locals > 0) {
		// reserve stack space for locals
		append_code_frag(unhexlify("4881ec")); // sub rsp, imm32
		// chall: misaligned stack necessary for functioning writes
		append_code_imm<int32_t>(func.n_locals * sizeof(int32_t)); // imm32 (no overflow possible)
	}

	while (get_curr_bytecode_buf_offs() < func.len) {
		scan_and_compile_op();
		if (is_dead && pending_relocs.empty()) {
			// dead + no outstanding relocs == dead-dead
			break;
		}
	}
	if (!pending_relocs.empty()) {
		// We've compiled all the code and there's still unresolved relocs
		std::abort();
	}
	if (!is_dead) {
		// stack check for "fallthrough" return
		if (stack_height < func.n_ret) {
			std::abort();
		}
	}

	// flush return relocations
	for (auto rel : ret_relocs) {
		write_reloc(rel, curr_asm_addr);
	}

	write_retval_mover(*this);
	// leave; ret;
	append_code_frag(unhexlify("c9c3"));

	auto new_top = (-FUNC_ALIGN) & (reinterpret_cast<std::size_t>(curr_asm_addr) + (FUNC_ALIGN - 1));
	// nop pad
	std::fill(reinterpret_cast<uint8_t*>(curr_asm_addr), reinterpret_cast<uint8_t*>(new_top), 0x90);

	seg_code.seg.set_prot(PROT_READ | PROT_EXEC);

	seg_code.top = reinterpret_cast<void*>(new_top);

	return func_addr;
}

} // namespace rp2sm

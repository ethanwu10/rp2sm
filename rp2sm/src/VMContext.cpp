#include <rp2sm/rp2sm.hpp>
#include "VMContext.hpp"
#include "FunctionCompiler.hpp"

#include <cstdlib>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <algorithm>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <sys/mman.h>

using std::size_t;
using std::ptrdiff_t;

namespace rp2sm {

VMContext::VMContext() :
	impl(std::make_unique<Impl>())
{}

VMContext::VMContext(VMContext&&) noexcept = default;
VMContext& VMContext::operator=(VMContext&&) noexcept = default;
VMContext::~VMContext() = default;

namespace {

struct BytecodeHeader {

	struct alignas(4) SegmentHeader {
		uint32_t offset;
		uint32_t file_size;
		uint32_t mem_size;
	};

	struct alignas(4) FuncTableEntry {
		uint32_t offset;
		uint32_t len;
		uint8_t n_args;
		uint8_t n_ret;
		uint8_t n_locals;
	};

	uint8_t magic[8];
	static constexpr uint8_t magic_value[8] = {0x7f, 'r', 'p', '2', 's', 'm', '\r', '\0'};

	SegmentHeader sh_rodata;
	SegmentHeader sh_data;
	uint16_t n_functions;
};

static_assert(offsetof(BytecodeHeader, sh_rodata) == 0x8);
static_assert(offsetof(BytecodeHeader, sh_data) == 0x14);
static_assert(offsetof(BytecodeHeader, n_functions) == 0x20);
static_assert(sizeof(BytecodeHeader) == 0x24);
static_assert(sizeof(BytecodeHeader::SegmentHeader) == 0xc);
static_assert(sizeof(BytecodeHeader::FuncTableEntry) == 0xc);

struct PageSizeGetter {
	size_t page_size;

	PageSizeGetter() :
		page_size(sysconf(_SC_PAGE_SIZE))
	{}

	constexpr operator size_t() const { return page_size; }
};
const PageSizeGetter page_size{};

} // namespace

[[gnu::naked]]
void VMContext::Impl::tramp_j_compile_func() {
	// Index should be placed in rsi by the resolver shim
	asm (
		"push %rbp\n"
		"push %r15\n"
		"push %r14\n"
		"push %r13\n"
		"mov %rsp, %rbp\n"
		// align stack
		"and $-0x10, %rsp\n"
		"mov %r15, %rdi\n"
	);
	asm (
		// load rax here
		"call *%0\n"
		"mov %%rbp, %%rsp\n"
		"pop %%r13\n"
		"pop %%r14\n"
		"pop %%r15\n"
		"pop %%rbp\n"
		"jmp *%%rax\n"
		:: "rax" (tramp_t_compile_func)
	);
}

VMContext VMContext::create(void* _code_buf, std::size_t len) {
	auto code_buf = reinterpret_cast<uint8_t*>(_code_buf);

	if (len < sizeof(BytecodeHeader)) {
		std::abort();
	}

	BytecodeHeader& header = *reinterpret_cast<BytecodeHeader*>(code_buf);
	if (
		std::memcmp(header.magic, BytecodeHeader::magic_value, sizeof(header.magic)) != 0 ||
		header.sh_rodata.offset + header.sh_rodata.file_size > len ||
		header.sh_data.offset + header.sh_data.file_size > len ||
		header.n_functions * sizeof(BytecodeHeader::FuncTableEntry) + sizeof(BytecodeHeader) > len
	) {
		std::abort();
	}
	auto* func_table = reinterpret_cast<BytecodeHeader::FuncTableEntry*>(code_buf + sizeof(BytecodeHeader));
	for (decltype(header.n_functions) i = 0; i < header.n_functions; i++) {
		if (func_table[i].offset + func_table[i].len > len) {
			std::abort();
		}
	}

	VMContext ctx{};
	Impl& impl = *ctx.impl;

	impl.seg_rodata = SegmentInfo::mmap(header.sh_rodata.mem_size, PROT_READ | PROT_WRITE);
	impl.seg_data = SegmentInfo::mmap(header.sh_data.mem_size, PROT_READ | PROT_WRITE);
	memcpy(impl.seg_rodata.base, code_buf + header.sh_rodata.offset, header.sh_rodata.file_size);
	memcpy(impl.seg_data.base, code_buf + header.sh_data.offset, header.sh_data.file_size);
	impl.seg_rodata.set_prot(PROT_READ);

	impl.c_st.functions.reset(header.n_functions);
	for (decltype(header.n_functions) i = 0; i < header.n_functions; i++) {
		const auto& entry = func_table[i];
		impl.c_st.functions[i] = FunctionInfo{
			.code_buf = code_buf + entry.offset,
			.len = entry.len,
			.n_args = entry.n_args,
			.n_ret = entry.n_ret,
			.n_locals = entry.n_locals,
		};
	}

	auto& c_st = impl.c_st;

	c_st.seg_got = SegmentInfo{
		impl.arena_ptr,
		page_size
	};

	// TODO: do not allocate whole rest of arena as code
	c_st.seg_code = CodeSegManager{
		SegmentInfo{
			reinterpret_cast<uint8_t*>(c_st.seg_got.base) + c_st.seg_got.len,
			Impl::ARENA_SZ - c_st.seg_got.len,
		},
	};

	c_st.seg_got.set_prot(PROT_READ | PROT_WRITE);
	c_st.seg_code.seg.set_prot(PROT_READ | PROT_WRITE);

	c_st.init_gotplt(&Impl::tramp_j_compile_func);

	c_st.seg_got.set_prot(PROT_READ);
	c_st.seg_code.seg.set_prot(PROT_READ | PROT_EXEC);

	return ctx;
}

void* VMContext::Impl::tramp_t_compile_func(Impl* ctx, func_index_t func_index) {
	const FunctionInfo& fi = ctx->c_st.functions[func_index];
	FunctionCompiler compiler{fi, ctx->c_st};
	void* compiled = compiler.compile();
	// TODO: move GOT write to compiler?
	ctx->c_st.seg_got.set_prot(PROT_READ | PROT_WRITE);
	ctx->c_st.get_got_entry_for_func(func_index) = compiled;
	ctx->c_st.seg_got.set_prot(PROT_READ);
	return compiled;
}

void VMContext::invoke(uint16_t func_index, StackFragment arguments, StackFragment returns) {
	static_assert(std::is_same_v<decltype(func_index), func_index_t>);

	const FunctionInfo& fi = impl->c_st.functions.get(func_index);
	if (std::get<1>(arguments) != fi.n_args ||
		std::get<1>(returns) < fi.n_ret) {
		std::abort();
	}
	auto jit_fn = impl->c_st.get_got_entry_for_func(func_index);
	auto reserved_stack = std::max(std::get<1>(arguments), std::get<1>(returns));

	// BEGIN CALL

	uint64_t* p_rets = std::get<0>(returns);
	size_t n_rets = std::get<1>(returns);

	register void*  t_rsi asm ("rsi") = std::get<0>(arguments); // arg copy source
	register size_t t_rcx asm ("rcx") = std::get<1>(arguments); // arg copy count
	// offset for arguments destination
	register size_t t_rdi asm ("rdi") = (reserved_stack - std::get<1>(arguments)) * sizeof(size_t);

	register void* rc_jit_fn asm ("rax") = jit_fn; // arbitrary register
	register size_t rs_reserved_stack asm ("rbp") = reserved_stack * sizeof(size_t);
	// registers set as part of JIT calling convention
	register void* rs_impl asm ("r15") = impl.get();
	register void* rs_rodata_base asm ("r14") = impl->seg_rodata.base;
	register void* rs_data_base asm ("r13") = impl->seg_data.base;

	asm volatile (
		"sub %[s], %%rsp\n"
		// rsp moved, no memory operands allowed
		"add %%rsp, %%rdi\n"
		"repne movsq\n"
		"call *%[fn]\n"
		"add %[s], %%rsp\n"
		// rsp fixed, memory operands allowed again
		"mov %[nr], %%rcx\n"
		"neg %%rcx\n"
		"lea (%%rsp, %%rcx, 8), %%rsi\n"
		"neg %%rcx\n"
		"mov %[r], %%rdi\n"
		"repne movsq\n"
		: // no direct outputs
		  // temporaries
		  [rsi] "+&r" (t_rsi),
		  [rcx] "+&r" (t_rcx),
		  [rdi] "+&r" (t_rdi),
		  // clobbered register inputs
		  [fn] "+&r"  (rc_jit_fn)
		: // inputs
		  [r]  "m"  (p_rets),
		  [nr] "m"  (n_rets),
		  [s]  "r"  (rs_reserved_stack),
		       "r"  (rs_impl),
		       "r"  (rs_data_base),
		       "r"  (rs_rodata_base)
		: "cc", "memory",
		  // lock down remaining registers
		  "rdx", "rbx", "r8", "r9", "r10", "r11", "r12"
		  // r14 saved
	);

	// END CALL
}

} // namespace rp2sm

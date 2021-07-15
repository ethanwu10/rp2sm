#include "CompilerState.hpp"

#include "support.hpp"
#include <cstddef>

namespace rp2sm {

namespace {

struct AsmState {
	CompilerState& st;

	void* curr_asm_addr;

	constexpr explicit AsmState(CompilerState& st) :
		st(st), curr_asm_addr(st.seg_code.top)
	{}


	// TODO: deduplicate this code with FunctionCompiler

	void append_code_frag(auto frag) {
		curr_asm_addr = std::copy(frag.begin(), frag.end(), reinterpret_cast<uint8_t*>(curr_asm_addr));
	}
	void append_code_imm(std::integral auto v) {
		auto* p = reinterpret_cast<decltype(v)*>(curr_asm_addr);
		*p = v;
		curr_asm_addr = p + 1;
	}

	void write_reloc(void* reloc_addr, void* target) {
		// reloc_addr points to disp32 for rip-relative addr in last bytes of
		// instruction (i.e. `rip` is reloc_addr + 4)
		auto offset =
			reinterpret_cast<uint8_t*>(target) -
			(reinterpret_cast<uint8_t*>(reloc_addr) + 4);
		static_assert(std::is_same_v<decltype(offset), std::ptrdiff_t>);
		*reinterpret_cast<int32_t*>(reloc_addr) = checked_narrow<int32_t>(offset);
	}

	void write_reloc_now(void* target) {
		write_reloc(curr_asm_addr, target);
		curr_asm_addr = reinterpret_cast<uint8_t*>(curr_asm_addr) + 4;
	}
};

} // namespace

void CompilerState::init_gotplt(void (*tramp_compile_func)()) {
	auto st = AsmState{*this};
	func_index_t n_funcs = functions.size();

	if ((reinterpret_cast<size_t>(st.curr_asm_addr) & 0xf) != 0) {
		// sanity check before starting (not optimized out)
		std::abort();
	}

	pltstubs.reset(N_SYS_FUNCS + n_funcs);

	get_got()[0] = reinterpret_cast<void*>(tramp_compile_func);

	auto _t_st = reinterpret_cast<uint8_t*>(st.curr_asm_addr);

	// alignment sanity check - should get fully optimized out by clang if
	// the alignment is correct since the instruction sequences are fixed lengths
#define ALIGN_CHECK() do { \
	if (((reinterpret_cast<uint8_t*>(st.curr_asm_addr) - _t_st) & 0xf) != 0) { \
		std::abort(); \
	} \
	_t_st = reinterpret_cast<uint8_t*>(st.curr_asm_addr); \
} while(0)

	// write compile func trampoline
	pltstubs[0] = st.curr_asm_addr;
	st.append_code_frag(unhexlify("ff25")); // jmp qword [rip+disp32]
	st.write_reloc_now(&get_got()[0]); // disp32
	st.append_code_frag(unhexlify("662e0f1f040500000000")); // nop (10 bytes)

	ALIGN_CHECK();

	for (func_index_t i = 0; i < n_funcs; i++) {
		auto tbl_idx = get_idx_for_func(i);

		pltstubs[tbl_idx] = st.curr_asm_addr;
		st.append_code_frag(unhexlify("ff25")); // jmp qword [rip+disp32]
		st.write_reloc_now(&get_got_entry_for_func(i)); // disp32
		get_got_entry_for_func(i) = st.curr_asm_addr; // got <- continuation
		st.append_code_frag(unhexlify("be")); // mov esi, imm32
		st.append_code_imm<int32_t>(i); // imm32
		st.append_code_frag(unhexlify("e9")); // jmp rel32
		st.write_reloc_now(pltstubs[0]); // rel32

		ALIGN_CHECK();
	}

#undef ALIGN_CHECK

	seg_code.top = st.curr_asm_addr;
}

} // namespace rp2sm

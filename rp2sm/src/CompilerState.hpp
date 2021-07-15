#ifndef RP2SM_COMPILERSTATE_HPP
#define RP2SM_COMPILERSTATE_HPP

#include "ContextMem.hpp"
#include "DynArray.hpp"

namespace rp2sm {

using func_index_t = uint16_t;
constexpr func_index_t N_SYS_FUNCS = 1;

struct FunctionInfo {
	void* code_buf;
	std::size_t len;

	uint8_t n_args;
	uint8_t n_ret;
	uint8_t n_locals;
};

struct CompilerState {
	SegmentInfo seg_got{};
	CodeSegManager seg_code{};

	DynArray<FunctionInfo> functions;

	DynArray<void*> pltstubs;

	[[nodiscard]]
	void** get_got() const {
		return reinterpret_cast<void**>(seg_got.base);
	}

	constexpr func_index_t get_idx_for_func(func_index_t func_index) const {
		return func_index + N_SYS_FUNCS;
	}

	// Returned function is in JIT calling convention
	// func_index must be valid, it is not checked!
	[[nodiscard]]
	auto get_got_entry_for_func(func_index_t func_index) const -> void*& {
		return get_got()[get_idx_for_func(func_index)];
	}

	// Initializes GOT and PLT stubs; assumes GOT and PLT are both rw-
	void init_gotplt(void (*tramp_compile_func)());
};

} // namespace rp2sm

#endif // RP2SM_COMPILERSTATE_HPP

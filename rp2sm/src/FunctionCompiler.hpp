#ifndef RP2SM_FUNCTIONCOMPILER_HPP
#define RP2SM_FUNCTIONCOMPILER_HPP

#include "CompilerState.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <list>
#include <algorithm>
#include <concepts>

namespace rp2sm {

using label_idx_t = uint16_t;

// fixed at 8 bits from file headers + x86 operand sizes
using local_idx_t = uint8_t;
using arg_idx_t = uint8_t;

struct FunctionCompiler {
	static constexpr std::size_t FUNC_ALIGN = 1ull << 4;

	struct Relocation {
		// 32 bit relative
		void* addr;
		label_idx_t target;
	};

	const FunctionInfo& func;
	CompilerState& st;

	std::size_t stack_height{0};
	void* curr_asm_addr{};
	void* curr_bytecode_addr{};

	std::vector<void*> labels;
	std::list<Relocation> pending_relocs;
	std::vector<void*> ret_relocs;

	bool is_dead{false};

	std::size_t get_curr_bytecode_buf_offs() const {
		return reinterpret_cast<size_t>(curr_bytecode_addr) - reinterpret_cast<size_t>(func.code_buf);
	}

	template <std::integral T>
	T bytecode_read_imm() const {
		return *reinterpret_cast<T*>(curr_bytecode_addr);
	}

	void append_code_frag(auto frag) {
		curr_asm_addr = std::copy(frag.begin(), frag.end(), reinterpret_cast<uint8_t*>(curr_asm_addr));
	}
	void append_code_imm(std::integral auto v) {
		auto* p = reinterpret_cast<decltype(v)*>(curr_asm_addr);
		*p = v;
		curr_asm_addr = p + 1;
	}

	void scan_and_compile_op();

	FunctionCompiler(const FunctionInfo& func, CompilerState& st) :
		func(func), st(st)
	{}

	// returns address of compiled function
	void* compile();
};

} // namespace rp2sm

#endif // RP2SM_FUNCTIONCOMPILER_HPP

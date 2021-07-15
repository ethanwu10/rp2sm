#ifndef RP2SM_VMCONTEXT_HPP
#define RP2SM_VMCONTEXT_HPP

#include <rp2sm/rp2sm.hpp>
#include "ContextMem.hpp"
#include "CompilerState.hpp"
#include "DynArray.hpp"

#include <cstdint>
#include <cstddef>

#include <sys/mman.h>

namespace rp2sm {

struct VMContext::Impl {
	static constexpr size_t ARENA_SZ{1llu << 31};

	void* arena_ptr;

	SegmentInfo seg_rodata{};
	SegmentInfo seg_data{};

	CompilerState c_st{};

	explicit Impl() :
		arena_ptr(
			mmap(nullptr, ARENA_SZ,
				PROT_NONE,
				MAP_PRIVATE | MAP_ANONYMOUS,
				-1, 0
			)
		)
	{}

	~Impl() {
		munmap(arena_ptr, ARENA_SZ);
		seg_rodata.unmap();
		seg_data.unmap();
	}

	Impl(const Impl&) = delete;
	Impl& operator=(const Impl&) = delete;
	Impl(const Impl&&) = delete;
	Impl& operator=(Impl&&) = delete;

	// Trampoline targets
	static void* tramp_t_compile_func(Impl* ctx, func_index_t func_index);

	// Trampolines
	static void tramp_j_compile_func();
};

} // namespace rp2sm

#endif // RP2SM_VMCONTEXT_HPP

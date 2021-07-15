#ifndef RP2SM_CONTEXTMEM_HPP
#define RP2SM_CONTEXTMEM_HPP

#include <utility>
#include <cstddef>
#include <cstdlib>
#include <sys/mman.h>

namespace rp2sm {

struct SegmentInfo {
	void* base{nullptr};
	std::size_t len{0};

	SegmentInfo() = default;
	SegmentInfo(void* base, std::size_t len) :
		base(base), len(len)
	{}

	SegmentInfo(const SegmentInfo&) = delete;
	SegmentInfo& operator=(const SegmentInfo&) = delete;

	SegmentInfo(SegmentInfo&&) = default;
	SegmentInfo& operator=(SegmentInfo&&) = default;

	void set_prot(int newProt) {
		if (mprotect(base, len, newProt) != 0) {
			std::abort();
		}
	}

	// TODO: split into separate managed object?
	[[nodiscard]]
	static SegmentInfo mmap(std::size_t len, int prot) {
		if (len == 0) {
			return SegmentInfo{nullptr, 0};
		}
		void* p = ::mmap(nullptr, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) {
			std::abort();
		}
		return SegmentInfo{p, len};
	}

	int unmap() {
		if (base == nullptr && len == 0) {
			return 0;
		}
		return munmap(base, len);
	}
};

struct CodeSegManager {
	SegmentInfo seg;

	void* top;

	constexpr CodeSegManager() : seg({}), top(nullptr) {}

	constexpr explicit CodeSegManager(SegmentInfo seg) :
		seg(std::move(seg)), top(seg.base)
	{}
};

} // namespace rp2sm

#endif // RP2SM_CONTEXTMEM_HPP

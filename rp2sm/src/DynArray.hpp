#ifndef RP2SM_DYNARRAY_HPP
#define RP2SM_DYNARRAY_HPP

#include <cstddef>
#include <cstdlib>
#include <memory>
#include <algorithm>

namespace rp2sm {

template <typename T>
class DynArray {
private:
	std::unique_ptr<T[]> data;
	std::size_t len;

public:
	constexpr DynArray() : data({}), len(0) {}
	constexpr explicit DynArray(std::size_t len) :
		data(new T[len]), len(len)
	{}

	constexpr T& operator[](std::size_t idx) {
		return data[idx];
	}

	constexpr T& get(std::size_t idx) {
		if (idx >= len) {
			std::abort();
		}
		return data[idx];
	}

	constexpr std::size_t size() const {
		return len;
	}

	constexpr void reset(std::size_t new_len) {
		// chall: use .reset with raw new over make_unique because clang optimizes better
		data.reset(new T[new_len]);
		len = new_len;
	}

	constexpr void resize(std::size_t new_len) {
		std::unique_ptr<T[]> old = std::move(data);
		std::size_t old_len = len;
		reset(new_len);
		std::move(old.get(), old.get() + std::min(old_len, new_len), data.get());
	}
};

} // namespace rp2sm

#endif // RP2SM_DYNARRAY_HPP

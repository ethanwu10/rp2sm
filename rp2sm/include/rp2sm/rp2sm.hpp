#ifndef RP2SM_RP2SM_HPP
#define RP2SM_RP2SM_HPP
#include <cstdint>
#include <memory>
#include <tuple>

#include <rp2sm/rp2sm_export.h>

namespace rp2sm {


class RP2SM_EXPORT VMContext {
public:
	struct RP2SM_NO_EXPORT Impl;
private:
	std::unique_ptr<Impl> impl;

	RP2SM_NO_EXPORT explicit VMContext();

public:
	[[nodiscard]]
	static VMContext create(void* code_buf, std::size_t len);

	VMContext(VMContext&&) noexcept;
	VMContext& operator=(VMContext&&) noexcept;

	~VMContext();

	using StackFragment = std::tuple<uint64_t*, uint8_t>;

	/**
	 * Invoke a function on this instance
	 *
	 * @param func_index index of function to invoke
	 * @param arguments  arguments to function
	 * @param returns    (out-param) return values of function (can be aliased)
	 */
	void invoke(uint16_t func_index, StackFragment arguments, StackFragment returns);
};

} // namespace rp2sm

#endif // RP2SM_RP2SM_HPP

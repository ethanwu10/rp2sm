#include <cstdint>
#include <concepts>
#include <utility>
#include <type_traits>
#include <array>
#include <stdexcept>
#include <cstdlib>

consteval uint8_t parse_hexnibble(char ch) {
	if (ch >= '0' && ch <= '9') {
		return ch - '0';
	}
	if (ch >= 'a' && ch <= 'f') {
		return ch - 'a' + 10;
	}
	if (ch >= 'A' && ch <= 'F') {
		return ch - 'A' + 10;
	}
	throw std::invalid_argument{"Not a hex character"};
}

template <size_t N>
consteval std::array<uint8_t, N/2> unhexlify(const char (&str)[N]) {
	std::array<uint8_t, N/2> ret;
	for (size_t i = 0; i < N/2; i++) {
		ret[i] = (parse_hexnibble(str[i * 2]) << 4) | parse_hexnibble(str[i * 2 + 1]);
	}
	return ret;
}

// narrowing casts borrowed from gsl, changed to abort instead of throw

// narrow_cast(): a searchable way to do narrowing casts of values
template <class T, class U>
constexpr T narrow_cast(U&& u) noexcept {
	return static_cast<T>(std::forward<U>(u));
}

// checked_narrow(): a checked narrow_cast() that aborts if the original value did not fit
template <std::integral T, typename U>
constexpr T checked_narrow(U&& u) {
	constexpr const bool is_different_signedness =
		(std::is_signed<T>::value != std::is_signed<U>::value);
	using U_ = std::remove_reference_t<U>;

	const T t = narrow_cast<T>(u);

	if (
		static_cast<U_>(t) != u ||
		(is_different_signedness && ((t < T{}) != (u < U_{})))
	) {
		std::abort();
	}

	return t;
}

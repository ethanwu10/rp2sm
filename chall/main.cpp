#include <rp2sm/rp2sm.hpp>
#include <cstdint>
#include <cstdio>
#include <memory>

#include <cmath>

namespace {

FILE* h_urandom;

[[gnu::noinline]]
bool is_prime(uint32_t n) {
	if ((n & 1) == 0) {
		return n == 2;
	}

	uint32_t upper_bound = std::ceil(std::sqrt(n));

	for (uint32_t i = 3; i <= upper_bound; i += 2) {
		if (n % i == 0) {
			return false;
		}
	}
	return true;
}

[[gnu::noinline]]
uint32_t gen_random_prime() {
	uint32_t num;
	fread(&num, sizeof(num), 1, h_urandom);
	num |= 1 | (1u << 31);
	while (!is_prime(num)) {
		num += 2;
	}
	if (num < (1u << 31)) {
		return gen_random_prime();
	} else {
		return num;
	}
}

[[gnu::noinline]]
uint32_t rand_int_lt(uint32_t max) {
	uint32_t num;
	do {
		fread(&num, sizeof(num), 1, h_urandom);
	} while (num >= max);
	return num;
}

} // namespace

int main(int argc, char* argv[]) {
	bool use_file = argc > 1;

	uint16_t len;
	FILE* f;

	if (use_file) {
		f = fopen(argv[1], "r");
		fseek(f, 0, SEEK_END);
		len = ftell(f);
		fseek(f, 0, SEEK_SET);
	} else {
		putc('\005', stdout);
		fflush(stdout);
		fread(&len, sizeof(len), 1, stdin);
	}

	auto code = std::make_unique<uint8_t[]>(len);

	if (use_file) {
		fread(code.get(), 1, len, f);
		fclose(f);
	} else {
		fread(code.get(), 1, len, stdin);
	}

	h_urandom = fopen("/dev/urandom", "r");

	uint32_t prime = gen_random_prime();
	uint32_t n = rand_int_lt(1<<16);

	fclose(h_urandom);

#ifndef NDEBUG
	printf("%u %u\n", prime, n);
#endif

	auto ctx = rp2sm::VMContext::create(code.get(), len);

	uint64_t fargs[2] = {prime, n};
	uint64_t fret[1];
	auto fargss = rp2sm::VMContext::StackFragment{fargs, 2};
	auto frets = rp2sm::VMContext::StackFragment{fret, 1};
	ctx.invoke(0, fargss, frets);

#ifndef NDEBUG
	printf("%u\n", static_cast<uint32_t>(fret[0]));
#endif

	if ((static_cast<uint64_t>(static_cast<uint32_t>(fret[0])) * n) % static_cast<uint64_t>(prime) != 1) {
		putc('\004', stdout);
		return 1;
	}

#ifndef NDEBUG
	puts("Success");
#endif
	FILE* fp = fopen("flag1.txt", "r");
	if (fp == nullptr) {
		fputs("Could not open flag file!\n", stderr);
		return 2;
	}
	char flagbuf[0x100];
	fgets(flagbuf, sizeof(flagbuf), fp);
	fclose(fp);
	fputs(flagbuf, stdout);

	return 0;
}

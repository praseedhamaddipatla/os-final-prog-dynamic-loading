#pragma once

#include <cstdint>
#include "machine/machine.h"

// aslr helpers

// flip to false if u want same addrs every run (to debug)
constexpr bool ASLR_ON = true;

// gives back rand 64 bit num. rdrand if cpu has it, if not just tsc
inline uint64_t aslrRandom() {
  uint32_t a, b, c, d;

  // bit 30 of ecx in leaf 1 = rdrand is there
  cpuid(1, 0, &a, &b, &c, &d);
  if (c & (1u << 30)) {
    for (int i = 0; i < 10; i++) {
      uint64_t val = 0;
      unsigned char ok = 0;
      asm volatile("rdrand %0; setc %1" : "=&r"(val), "=qm"(ok) : : "cc");
      if (ok) return val;   // rdrand can fail sometimes so we retry
    }
  }

  // not great rand
  return rdtsc();
}
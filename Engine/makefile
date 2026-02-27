default:
	cargo build --release

check:
	cargo check

clean:
	cargo clean

# --- no_std targets ---

# Build for a baremetal target (no OS, no filesystem).
# Change the --target to match your ISA / board, for example:
#   aarch64-unknown-none      — ARMv8-A (Cortex-A, Raspberry Pi bare-metal)
#   riscv32imac-unknown-none-elf  — RISC-V 32-bit
#   riscv64gc-unknown-none-elf    — RISC-V 64-bit
#
# Requirements:
#   rustup toolchain install nightly
#   rustup component add rust-src --toolchain nightly
baremetal:
	cargo +nightly build --release --no-default-features -Zbuild-std=core,alloc --target aarch64-unknown-none

# Quick check that no_std compiles (no linker, host target).
check-baremetal:
	cargo check --no-default-features

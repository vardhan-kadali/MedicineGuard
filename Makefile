# ==============================================================================
# MedicineGuard - Phase 1 Makefile
# Standard C11, Zero External Dependencies
# ==============================================================================

CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O3 -Icore-c/include
BUILD_DIR = build
BIN_DIR = bin

OBJS = $(BUILD_DIR)/sha256.o $(BUILD_DIR)/merkle.o

all: dirs tests benchmark

dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

$(BUILD_DIR)/sha256.o: core-c/src/sha256.c core-c/include/sha256.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/merkle.o: core-c/src/merkle.c core-c/include/merkle.h core-c/include/sha256.h
	$(CC) $(CFLAGS) -c $< -o $@

tests: dirs $(OBJS)
	$(CC) $(CFLAGS) $(BUILD_DIR)/sha256.o core-c/tests/test_sha256.c -o $(BIN_DIR)/test_sha256
	$(CC) $(CFLAGS) $(OBJS) core-c/tests/test_merkle.c -o $(BIN_DIR)/test_merkle

benchmark: dirs $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) core-c/benchmarks/benchmark.c -o $(BIN_DIR)/benchmark

check: tests
	@echo "Running SHA-256 Tests..."
	@$(BIN_DIR)/test_sha256
	@echo "Running Merkle Tree Tests..."
	@$(BIN_DIR)/test_merkle

run-benchmark: benchmark
	@$(BIN_DIR)/benchmark

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all dirs tests benchmark check run-benchmark clean


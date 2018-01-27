#ifndef MAIN_H
#define MAIN_H

#include <inttypes.h>

#define DEBUG_ENCLAVE 1
#define REG_EIP 14

// enclave required files
void create_enclave(void);
void destroy_enclave(void);
void print_ocall(char* str);
void write_password_data(uint8_t *blob, uint32_t bloblen);
void write_secret_data(uint8_t *blob, uint32_t bloblen);
void write_tries_left_data(uint8_t *blob, uint32_t bloblen);
int read_password_data(uint8_t *buf, uint32_t buflen, uint32_t *buflen_out);
int read_secret_data(uint8_t *buf, uint32_t buflen, uint32_t *buflen_out);
int read_tries_left_data(uint8_t *buf, uint32_t buflen, uint32_t *buflen_out);
void enclave_thread(void);
void run_tests_1(void);
void run_tests_2(void);
void run_tests_3(void);

// part 1 tests
void test_get_secret_success(void);
void test_get_secret_fail(void);
void test_set_password_success(void);
void test_set_password_fail_with_ocall(void);
void test_set_password_fail(void);
void test_try_old_password(void);
void test_set_secret_success(void);
void test_set_secret_fail(void);
void test_lockout(void);

// for part 3
void test_part_3(void);
void test_part_3_2(void);


// for part 5
void install_fault_handler(void);
void fault_handler(int signo, siginfo_t* si, void* unused);
void test_check_tries_left(void);
void test_check_correct_guess_addr(void);
void test_check_incorrect_guess_addr(void);
void test_get_guess_addr_right(void);
void test_get_guess_addr_wrong(void);

#endif

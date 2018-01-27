#ifndef VAULT_H
#define VAULT_H

#include <stdint.h>
#include <stddef.h>
#include <sgx_tseal.h>
#include <sgx_key.h>
#include <sgx_trts.h>
#include <sgx_utils.h>

int get_secret(char* provided_password, char* out_secret, size_t len);
int set_password(char* provided_password, char* new_password);
int set_secret(char* provided_password, char* new_secret);
int get_number_of_tries_left(void);
char* get_correct_password_address(void);
int get_secret_attack( char* provided_password, uint64_t out, size_t len);
void* get_handle_correct_guess_address(void);
void* get_handle_incorrect_guess_address(void);
int authenticate(char* provided_password);
void save_state(void);
void save_state_helper(int i);
void fetch_state(void);

#endif

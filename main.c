#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <SGX/sgx_urts.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <malloc.h>
#include <setjmp.h>
#include "Enclave/vault_u.h"
#include "main.h"

/*
 * ssh cs1617reardon@skylake004.cs.kuleuven.be
 * 2c90790a85
 */

static void* 												handle_correct_guess_addr;
static void* 												handle_incorrect_guess_addr;
static char* 												password;
static int 													counter = 1;
static int													flag = 0;

static sgx_enclave_id_t 						eid = 2;
static sgx_launch_token_t 				  token = {0};

static sigjmp_buf*                  recover;
static sigjmp_buf*									recover2;
static volatile sig_atomic_t        canjump;

static uint8_t 											sealed_password[1024];
static uint32_t 										sealed_password_size = 0;
static uint8_t 											sealed_secret[1024];
static uint32_t 										sealed_secret_size = 0;
static uint8_t 											sealed_tries_left[1024];
static uint32_t 										sealed_tries_left_size = 0;

void debug(void) {
	for (size_t i = 0; i < 1024; i++) {
		printf("%u", token[i]);
	}
}

int main( int argc, char **argv )
{
	password = (char*)malloc(100);

	install_fault_handler();

	enclave_thread();
}

void enclave_thread(void) {
	create_enclave();
	sigjmp_buf mainbuf;

	if (sigsetjmp(mainbuf, 1)) {
		create_enclave();
		sigjmp_buf subbuf;
		fflush(stderr);
		printf("\n\n\n");
		if (sigsetjmp(subbuf, 1)) {
			create_enclave();
			run_tests_3();
			destroy_enclave();
			exit(1);
		}
		canjump = 1;
		run_tests_2();

		recover2 = &subbuf;

		printf(" ___________________________\n");
		printf("|                           |\n");
		printf("|    Test Wrong PW Addr     |\n");
		printf("|                           |\n");
		printf("|___________________________|\n");
		printf("\n\n\n");

		test_get_guess_addr_wrong();
		test_check_incorrect_guess_addr();

		exit(1);

		}

		run_tests_1();

		recover = &mainbuf;
		canjump = 1;

		sleep(1);
		printf(" ___________________________\n");
		printf("|                           |\n");
		printf("|    Test Right PW Addr     |\n");
		printf("|                           |\n");
		printf("|___________________________|\n");
		printf("\n\n\n");
		test_get_guess_addr_right();
		test_check_correct_guess_addr();
}


void print_ocall(char* str) {
	printf("%s\n", str);
}

/*
 * bootstraps the enclave
 */
void create_enclave(void) {
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;
	if ( SGX_SUCCESS != ( ret = sgx_create_enclave( "./Enclave/vault.so", DEBUG_ENCLAVE, &token, &updated, &eid, NULL ) ) )
	{
		printf( "Failed to create enclave\n" );
		exit(-1);
	}
	if (flag == 0) {
		flag = 1;
	} else {
		// reload the state into the enclave
	}
}

/*
 * destroys the enclave
 */
void destroy_enclave(void) {
	sgx_status_t ret = SGX_SUCCESS;

	if ( SGX_SUCCESS != (ret = sgx_destroy_enclave( eid ) ) )
	{
		printf( "Error destroying enclave (error 0x%x)\n", ret );
	} else printf("Enclave destroyed\n");
	exit(-3);
}

/*
 * runs all of the tests
 */
void run_tests_1(void) {
	printf("Beginning to run the tests\n\n\n");
	strcpy(password, "empty");
	printf(" ___________________________\n");
	printf("|                           |\n");
	printf("|   Test Setting Password   |\n");
	printf("|                           |\n");
	printf("|___________________________|\n");
	printf("\n\n\n");

	test_set_password_success();
	test_set_password_fail_with_ocall();
	test_set_password_fail();
	sleep(1);
	printf(" ___________________________\n");
	printf("|                           |\n");
	printf("|    Test Setting Secret    |\n");
	printf("|                           |\n");
	printf("|___________________________|\n");
	printf("\n\n\n");
	test_set_secret_success();
	test_set_secret_fail();
}


void run_tests_2(void) {
	sleep(1);
	printf(" ___________________________\n");
	printf("|                           |\n");
	printf("|    Test Getting Secret    |\n");
	printf("|                           |\n");
	printf("|___________________________|\n");
	printf("\n\n\n");

	test_get_secret_success();
	test_get_secret_fail();
	sleep(1);
}

void run_tests_3(void) {
	printf("\n\n\n");
	test_check_tries_left();
	sleep(1);
	printf(" ___________________________\n");
	printf("|                           |\n");
	printf("|  Test Resetting Password  |\n");
	printf("|                           |\n");
	printf("|___________________________|\n");
	printf("\n\n\n");
	test_part_3();
	test_lockout();
	test_part_3_2();
}
/*
 * for part 5: handles the segnmentation faults given
 * to us after we memory protect them
 * the faults will be handled as followed:
 		* the first attempt will be a wrong password attempt,
 		* and a proof of concept that the amount of tries
		* does not decrease
		* the second will show a proof of concept of the correct_address
		* password and will return to the enclave
 */
void fault_handler(int signo, siginfo_t* si, void* unused) {
  if (signo == SIGSEGV) {
    printf("Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
		long addr = (long) si->si_addr;
		if (addr == (long) handle_correct_guess_addr) {
			if (mprotect(handle_correct_guess_addr, 4096, PROT_WRITE) == -1){
				printf("Error making the pages read only");
				exit(1);
			}
			printf("You used the correct password \"%s\"\n", password);
			canjump = 0;
			siglongjmp(*recover, 1);
		} else {
			if (mprotect(handle_incorrect_guess_addr, 4096, PROT_WRITE) == -1){
				printf("Error making the pages read only");
				exit(1);
			}
			printf("You used an incorrect password\n");
			canjump = 0;
    	siglongjmp(*recover2, 1);
		}
  }
}

/*
 * for part 5: adds the neccessary code to
 * start handling the page faults
 */
void install_fault_handler(void) {
  struct sigaction act, segv_oact;
  memset(&act, sizeof(sigaction), 0);
  act.sa_sigaction = fault_handler;
  //Block all signals while the SIGSEGV signal is handled
  sigfillset(&act.sa_mask);
  //The signal handler takes 3 arguments, not one. In this case, sa sigaction should be
  // set instead of sa handler.
  act.sa_flags = SA_RESTART | SA_SIGINFO;
  //Register handler
  sigaction(SIGSEGV, &act, &segv_oact);
}


void test_get_secret_success(void) {
	printf("Test %i: successfully get the secret using the correct password\n", counter);
  sgx_status_t ret = SGX_SUCCESS;
	char* secret = (char*)malloc(100);
	size_t len = 100;
	unsigned int output;

	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, password, secret, len ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (output) {
			printf("Success: retrieved the secret \"%s\" correctly\n", secret);
		}
		else
			printf("Failed: unable to retrieve the secret\n");
	}
	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else
		printf("The number of tries left is: %i\n", output);

	printf("\n\n\n");
	free(secret);
}

/*
 * tests whether the get secret performs correctly
 * when the password is incorrect and that the amount of
 * tries left decreases
 */
void test_get_secret_fail(void) {
	printf("Test %i: use an incorrect password to try and get the secret\n", counter );
  sgx_status_t ret = SGX_SUCCESS;
	char* wrong = "wrong";
	char* secret = (char*)malloc(100);
	size_t len = 100;
	unsigned int output;

	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, wrong, secret, len ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (!output) {
			printf("Success: was unable to retrieve the secret\n");
		}
		else
			printf("Failed: retrieved the secret \"%s\"\n", secret);
	}

	counter++;
	printf("\n\n\n");
	free(secret);

	test_check_tries_left();
}

/*
 * tests whether the password can be set correctly
 */
void test_set_password_success(void) {
	printf("Test %i: change the password from the default\n", counter);
  sgx_status_t ret = SGX_SUCCESS;
	char* new = "new_password";
	unsigned int output;

	if ( SGX_SUCCESS != (ret = set_password( eid, &output, password, new ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (output) {
			printf("Success: changed the password to \"%s\"\n", new);
			int length = strlen(new) + 1;
			memcpy(password, new, length);
		}
		else
			printf("Failed: was unable to change the password\n");
	}

	printf("\n\n\n");
	counter++;
}

/*
 * tests whether an incorrect password will be rejected
 * and an ocall will be outputted
 */
void test_set_password_fail_with_ocall(void) {
	printf("Test %i: fail to change the password due to a too long password\n", counter);
  printf("        expected to output an ocall\n" );
  sgx_status_t ret = SGX_SUCCESS;
	char* new = "new_password_is_ridiculously_long_for_our_poor_program";
	unsigned int output;

	if ( SGX_SUCCESS != (ret = set_password( eid, &output, password, new ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (!output) {
			printf("Success: was unable to change the password\n");
		}
		else {
			printf("Failed: changed the password to \"%s\"\n", new);
			int length = strlen(new) + 1;
			memcpy(password, new, length);
		}
	}

	printf("\n\n\n");
	counter++;
}

/*
 * tests whether the password change will be rejected when the
 * password is incorrect
 */
void test_set_password_fail(void) {
	printf("Test %i: fail to change the password due to giving an incorrect password\n", counter );
  sgx_status_t ret = SGX_SUCCESS;
	char* new = "who_cares";
	char* password2 = "wrong";
	unsigned int output;

	if ( SGX_SUCCESS != (ret = set_password( eid, &output, password2, new ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (!output) {
			printf("Success: was unable to change the password\n");
		}
		else {
			printf("Failed: changed the password to \"%s\"\n", new);
			int length = strlen(new) + 1;
			memcpy(password, new, length);
		}
	}

	printf("\n\n\n");
	counter++;
}

/*
 * tests whether an older password will be rejected
 */
void test_try_old_password(void) {
	printf("Test %i: try to get the secret using the old password\n", counter );
  sgx_status_t ret = SGX_SUCCESS;
	char* wrong = "empty";
	char* secret = (char*)malloc(100);
	size_t len = 100;
	unsigned int output;

	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, wrong, secret, len ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (!output) {
			printf("Success: could not retrieve the secret\n");
		}
		else
			printf("Failed: retrieved a secret\n");
	}

	printf("\n\n\n");
	free(secret);
	counter++;
	test_check_tries_left();
}

/*
 * tests if the secret will change
 */
void test_set_secret_success(void) {
	printf("Test %i: successfully change the secret\n", counter );
	sgx_status_t ret = SGX_SUCCESS;
	char* secret = "a_new_secret";
	unsigned int output;
	if ( SGX_SUCCESS != (ret = set_secret( eid, &output, password, secret ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (output) {
			printf("Success: set the secret to \"%s\" correctly\n", secret);
		}
		else
			printf("Failed: unable to change the secret\n");
	}

	printf("\n\n\n");
	counter++;
}

/*
 * tests if the secret will be changed if it's incorrect
 */
void test_set_secret_fail(void) {
	printf("Test %i: unsuccessfully change the secret\n", counter );
	sgx_status_t ret = SGX_SUCCESS;
	char* secret = "imma secret 2";
	char* wrong = "wrong";
	unsigned int output;

	if ( SGX_SUCCESS != (ret = set_secret( eid, &output, wrong, secret ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (!output) {
			printf("Success: was unable to set the secret\n");
		}
		else
			printf("Failed: set the secret to \"%s\" incorrectly\n", secret);
	}

	printf("\n\n\n");
	counter++;
}

/*
 * tests if the system correctly updates
 */
void test_lockout(void) {
	printf("Test %i: test if the program will lockout successfully\n", counter );
  printf("         after the tries goes to 0\n" );
	sgx_status_t ret = SGX_SUCCESS;
	char* wrong_password = "wrong";
	unsigned int output;
	unsigned int count;
	char* secret = (char*)malloc(100);
	size_t len = 100;

	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		printf("The number of tries left is: %i\n", output);
		printf("Running loop to send this to 0\n");
	}

	for(int count = output; count >= 0; count--) {
		if ( SGX_SUCCESS != (ret = get_secret( eid, &output, wrong_password, secret, len ) ) ){
			printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
			destroy_enclave();
		}
	}

	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		printf("Try and use the correct password to get the secret at %i\n", output);
	}

	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, "", secret, len ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (!output) {
			printf("Success: was unable to retrieve the secret\n");
		}
		else
			printf("Failed: retrieved the secret \"%s\"\n", secret);
	}

	printf("\n\n\n");
	counter++;
}

/*
 * tests the third part
 */
void test_part_3(void) {
	printf("Test %i: attempt to get the address of the password when the system is not locked out\n", counter);
	sgx_status_t ret = SGX_SUCCESS;
	char* address;

	if ( SGX_SUCCESS != (ret = get_correct_password_address( eid, &address) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (address) {
			printf("Success: the address is %p\n", address);
		}
		else
			printf("Failed: was unable to get the address\n");
	}
	printf("\n\n\n");
	counter++;

	printf("Test %i: attempt to get the secret when the system is not in lockout\n", counter);
	unsigned int output;
	size_t len = 100;
	char* wrong = "123456789";
	if ( SGX_SUCCESS != (ret = get_secret_attack( eid, &output, wrong, (uint64_t) address, len ) ) ){
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}

	char* secret = (char*)malloc(100);

	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, "", secret, len ) ) ){
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (output) {
			printf("Success: retrieved the secret \"%s\" correctly using an empty password\n", secret);
		}
		else
			printf("Failed: unable to retrieve the secret\n");
	}
		printf("\n\n\n");
		counter++;
}

/*
 * tests the third part
 */
void test_part_3_2(void) {
	printf("Test %i: attempt to get the address of the password when the system is locked out\n" , counter);
	sgx_status_t ret = SGX_SUCCESS;
	char* address;

	if ( SGX_SUCCESS != (ret = get_correct_password_address( eid, &address) ) ){
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (address) {
			printf("Success: the address is %p\n", address);
		}
		else
			printf("Failed: was unable to get the address\n");
	}
	printf("\n\n\n");
	counter++;

	printf("Test %i: attempt to get the secret when the system is not in lockout\n", counter);
	unsigned int output;
	size_t len = 100;
	char* wrong = "123456789";
	if ( SGX_SUCCESS != (ret = get_secret_attack( eid, &output, wrong, (uint64_t) address, len ) ) ){
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}

	char* secret = (char*)malloc(100);

	if ( SGX_SUCCESS != (ret = get_secret( eid, &output, "", secret, len ) ) ){
		printf( "Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		if (output) {
			printf("Failed: retrieved the secret \"%s\" correctly using an empty password\n", secret);
		}
		else
			printf("Success: unable to retrieve the secret after the system has locked out\n");
	}
		printf("\n\n\n");
		counter++;
}

/*
 * Get the correct and incorrect guess addresses
 * and change this to read only protection
 */
void test_get_guess_addr_wrong(void) {
	void* output;
	int pagesize = 4096;
	sgx_status_t ret = SGX_SUCCESS;

	printf("Test %i: Getting the incorrect addresses\n        of the functions handling an incorrect\n        guess.  This will also make this have read only privileges.\n", counter);

	if ( SGX_SUCCESS != (ret = get_handle_incorrect_guess_address( eid, &output ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		handle_incorrect_guess_addr = output;
		printf("Success: got the incorrect guess address %p\n", (char*) handle_incorrect_guess_addr);
		if (mprotect(output, pagesize, PROT_READ) == -1){
			printf("Error making the pages read only");
			exit(1);
		}
	}

	counter++;
	printf("\n\n\n");
}

void test_get_guess_addr_right(void) {
	void* output;
	int pagesize = 4096;
	sgx_status_t ret = SGX_SUCCESS;

	printf("Test %i: Getting the correct addresses\n        of the functions handling an correct\n        guess.  This will also make this have read only privileges.\n", counter);

	if ( SGX_SUCCESS != (ret = get_handle_correct_guess_address( eid, &output ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else {
		handle_correct_guess_addr = output;
		printf("Success: got the correct guess address %p\n", (char*) handle_correct_guess_addr);
		if (mprotect(output, pagesize, PROT_READ) == -1){
			printf("Error making the pages read only");
			exit(1);
		}
	}

	counter++;
	printf("\n\n\n");
}


void test_check_tries_left(void) {
	unsigned int output;
	sgx_status_t ret = SGX_SUCCESS;

	printf("Test %i: Check the number of tries left\n", counter);

	if ( SGX_SUCCESS != (ret = get_number_of_tries_left( eid, &output ) ) ){
		printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
		destroy_enclave();
	}
	else
		printf("The number of tries left is: %i\n", output);

	printf("\n\n\n");
	counter++;
}


void test_check_incorrect_guess_addr(void) {
	printf("Test %i: Trigger a segnmentation fault using the wrong\n         password.\n", counter);
	unsigned int buf;
	char* secret = (char*)malloc(100);
	sgx_status_t ret = SGX_SUCCESS;
	counter++;

	if ( SGX_SUCCESS != (ret = get_secret( eid, &buf, "password", secret, 100 ) ) ){
			printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
			destroy_enclave();
		}
		else {
			if (buf) printf("Retrieved the secret \"%s\" correctly using an empty password\n", secret);
		}
	printf("\n\n\n");
	free(secret);
}

void test_check_correct_guess_addr(void) {
	printf("Test %i: Trigger a segnmentation fault using the right\n         password.\n", counter);
	unsigned int buf;
	char* secret = (char*)malloc(100);
	sgx_status_t ret = SGX_SUCCESS;
	counter++;

	if ( SGX_SUCCESS != (ret = get_secret( eid, &buf, password, secret, 100 ) ) ){
			printf( "Failed: Error calling enclave\n (error 0x%x)\n", ret );
			destroy_enclave();
		}
		else {
			if (buf) printf("Retrieved the secret \"%s\" correctly using the right password\n", secret);
		}
	printf("\n\n\n");
	free(secret);
}

int read_password_data(uint8_t *buf, uint32_t buflen, uint32_t *buflen_out)
{
  if (sealed_password_size == 0)
    return 1;

  if (buflen < sealed_password_size)
    return 1;

  memcpy(buf, sealed_password, sealed_password_size);
  *buflen_out = sealed_password_size;
  return 0;
}

int read_secret_data(uint8_t *buf, uint32_t buflen, uint32_t *buflen_out)
{
  if (sealed_secret_size == 0)
    return 1;

  if (buflen < sealed_secret_size)
    return 1;

  memcpy(buf, sealed_secret, sealed_secret_size);
  *buflen_out = sealed_secret_size;
  return 0;
}

int read_tries_left_data(uint8_t *buf, uint32_t buflen, uint32_t *buflen_out)
{
  if (sealed_tries_left_size == 0)
    return 1;

  if (buflen < sealed_tries_left_size)
    return 1;

  memcpy(buf, sealed_tries_left, sealed_tries_left_size);
  *buflen_out = sealed_tries_left_size;
  return 0;
}

void write_password_data(uint8_t *blob, uint32_t bloblen) {
	memcpy(sealed_password, blob, bloblen);
	sealed_password_size = bloblen;
}

void write_secret_data(uint8_t *blob, uint32_t bloblen) {
	memcpy(sealed_secret, blob, bloblen);
	sealed_secret_size = bloblen;
}

void write_tries_left_data(uint8_t *blob, uint32_t bloblen) {
	memcpy(sealed_tries_left, blob, bloblen);
	sealed_tries_left_size = bloblen;
}

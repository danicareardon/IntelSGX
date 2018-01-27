#include "vault.h"
#include "vault_t.h"
#include <string.h>
#include <stdlib.h>
#include "sgx_tseal.h"

#define DEFAULT_TRIES_LEFT			3
#define DEFAULT_PASSWORD_SIZE		20
#define DEFAULT_SECRET_SIZE     100
#define __TRUE									1
#define __FALSE									0

static int number_of_tries_left = DEFAULT_TRIES_LEFT;
static char secret[DEFAULT_SECRET_SIZE] = "empty";
static char password[DEFAULT_PASSWORD_SIZE] = "empty";
static char char_number_of_tries_left[1];

static int state = 0;

__attribute__((optimize("align-functions=4096")))
void handle_correct_guess(void) {
  int tries_left = get_number_of_tries_left();
  if (tries_left > 0 && tries_left <= DEFAULT_TRIES_LEFT) {
    number_of_tries_left = DEFAULT_TRIES_LEFT;
    save_state();
  }
}

__attribute__((optimize("align-functions=4096")))
void handle_incorrect_guess(void) {
  int tries_left = get_number_of_tries_left();
  if (tries_left > 0 && tries_left <= DEFAULT_TRIES_LEFT) {
    number_of_tries_left--;
    save_state();
  }
}

/*
 * if the provided password authenticates:
 *   handles the correct guess by resetting the
 *   tries to the default
 *   copies the secret into the out char*
 *   returns a __TRUE (1)
 * else decreases the number of tries left
 *   and returns a __FALSE (0)
 */
int get_secret (char* provided_password, char* out_secret, size_t len) {
  if (!state) {
    fetch_state();
    state = 1;
  }
  if (len < DEFAULT_SECRET_SIZE) {
    out_secret = (char*)malloc(DEFAULT_SECRET_SIZE);
  }
  if (authenticate (provided_password)) {
    handle_correct_guess();
    int length = strlen(secret) + 1;
    memcpy (out_secret, secret, length);
    return __TRUE;
  } else {
    handle_incorrect_guess();
    int length = strlen("\0") + 1;
    memcpy (out_secret, "\0", length);
    return __FALSE;
  }
}

/*
 * if the provided password authenticates:
 *   if the password is in the correct size limit
 *      return __TRUE (1)
 *   else
 *      print an ocall
 *      return a __FALSE (0)
 * else returns a __FALSE (0)
 */
int set_password (char* provided_password, char* new_password) {
  if (!state) {
    fetch_state();
    state = 1;
  }
  if (authenticate (provided_password)) {
    int length = strlen(new_password) + 1;
    if (length < DEFAULT_PASSWORD_SIZE) {
      memcpy (password, new_password, length);
      save_state();
      return __TRUE;
    }
    else {
      print_ocall("Not an acceptable password!");
      return __FALSE;
    }
  }
  else {
    return __FALSE;
  }
}

/*
 * if the provided password authenticates:
 *   copies the new_secret into the secret obj
 *   returns a __TRUE (1)
 * else returns a __FALSE (0)
 */
int set_secret (char* provided_password, char* new_secret) {
  if (!state) {
    fetch_state();
    state = 1;
  }
  if (authenticate (provided_password)) {
    int length = strlen(new_secret) + 1;
    if (length < DEFAULT_SECRET_SIZE) {
      memcpy(secret, new_secret, length);
      save_state();
      return __TRUE;
    }
  }
  return __FALSE;
}

/*
 * returns the number_of_tries_left obj
 */
int get_number_of_tries_left (void) {
  if (!state) {
    fetch_state();
    state = 1;
  }
  return number_of_tries_left;
}

/*
 * returns the address of the password obj
 * for part 3
 */
char* get_correct_password_address (void) {
  return &password[0];
 }

 /*
  * returns the secret
  * for part 3
  */
 int get_secret_attack (char* provided_password, uint64_t out, size_t len) {
   return get_secret(provided_password, (char*) out, len);
 }

/*
 * returns the address of the handle_correct_guess()
 * for part 5
 */
 void* get_handle_correct_guess_address (void) {
  return &handle_correct_guess;
}

/*
 * returns the address of the handle_incorrect_guess()
 * for part 5
 */
void* get_handle_incorrect_guess_address (void) {
     return &handle_incorrect_guess;
}

/*
 * authenticates the current password
 * compare the provided_password to the password
 * get the number of tries left
 * if the number of tries left > 0 and the string compare is 0
 *   return __TRUE (1)
 * else
 *   return __FALSE (0)
 */
int authenticate (char* provided_password) {
  int cmp = strncmp(provided_password, password, strlen(provided_password) + 1);
  int tries_left = get_number_of_tries_left();

  if (tries_left > 0 && tries_left <= DEFAULT_TRIES_LEFT) {
    if (cmp == 0) {
      return __TRUE;
    }
  }
  return __FALSE;
}

void fetch_state(void) {
  uint8_t blob[1024];
  char pw[DEFAULT_PASSWORD_SIZE];
  char sec[DEFAULT_SECRET_SIZE];
  char tries_left[1];

  uint32_t bloblen, pwlen, seclen, tllen;
  int err;

  // fetch the password
  if (read_password_data(&err, blob, sizeof blob, &bloblen))
    return;
  else {
    if (!err) {
      pwlen = sizeof(pw);
      if (sgx_unseal_data((const sgx_sealed_data_t *) blob, NULL, NULL, (uint8_t*) pw, &pwlen)){

        return;
      }
      memcpy(password, pw, sizeof(pw));
    }
  }

  // fetch the secret
  if (read_secret_data(&err, blob, sizeof blob, &bloblen))
    return;
  else {
    if (!err) {
      seclen = sizeof(sec);
      if (sgx_unseal_data((const sgx_sealed_data_t *) blob, NULL, NULL, (uint8_t*) sec, &seclen)){
        return;
      }
      memcpy(secret, sec, sizeof(sec));
    }
  }
  // fetch the tries left
  if (read_tries_left_data(&err, blob, sizeof blob, &bloblen))
    return;
  else {
    if (!err) {
      tllen = sizeof(tries_left);
      if (sgx_unseal_data((const sgx_sealed_data_t *) blob, NULL, NULL, (uint8_t*) tries_left, &tllen)){
        return;
      }

      tries_left[strlen(tries_left)-1] = 0;
      memcpy(char_number_of_tries_left, tries_left, sizeof(tries_left));

      if (strncmp(tries_left, "0", 1) == 0) {
        number_of_tries_left = 0;
      } else if (strncmp(tries_left, "1", 1) == 0) {
        number_of_tries_left = 1;
      } else if (strncmp(tries_left, "2", 1) == 0) {
        number_of_tries_left = 2;
      } else if (strncmp(tries_left, "3", 1) == 0) {
        number_of_tries_left = 3;
      }

    }
  }
}

void get_char_number_of_tries_left(void) {
  int tries_left = get_number_of_tries_left();
  if (tries_left == 0) {
    memcpy(char_number_of_tries_left, "0", sizeof("0"));
  } else if (tries_left == 1) {
    memcpy(char_number_of_tries_left, "1", sizeof("1"));
  } else if (tries_left == 2) {
    memcpy(char_number_of_tries_left, "2", sizeof("2"));
  } else if (tries_left == 3) {
    memcpy(char_number_of_tries_left, "3", sizeof("3"));
  }
}


void save_state(void) {
  save_state_helper(1);
  save_state_helper(2);
  save_state_helper(3);
}


void save_state_helper(int i) {
  uint32_t length;
  uint32_t need_len;
  int8_t* ptr;
  uint8_t buf[1024];

  if (i == 1) {
    get_char_number_of_tries_left();
    length = sizeof(char_number_of_tries_left);
    need_len = sgx_calc_sealed_data_size(0, length);
    ptr = (int8_t *) char_number_of_tries_left;
    if (sgx_seal_data(0, NULL, length, ptr, need_len, (sgx_sealed_data_t *) buf))
      return;
    write_tries_left_data(buf, need_len);

  } else if (i == 2) {
    length = sizeof(secret);
    need_len = sgx_calc_sealed_data_size(0, length);
    ptr = (int8_t *) secret;
    if (sgx_seal_data(0, NULL, length, ptr, need_len, (sgx_sealed_data_t *) buf))
      return;
    write_secret_data(buf, need_len);
  } else {
    length = sizeof(password);
    need_len = sgx_calc_sealed_data_size(0, length);
    ptr = (int8_t *) password;
    if (sgx_seal_data(0, NULL, length, ptr, need_len, (sgx_sealed_data_t *) buf))
      return;
    write_password_data(buf, need_len);
  }
}

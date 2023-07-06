#ifndef disk_encryption_h
#define disk_encryption_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <cryptsetup.h>
#include <errno.h>

#define CIPHER "aes"
#define CIPHER_MODE "cbc-essiv:sha256"
#define KEY_SIZE 128

int format_disk(const char* device_name, const char* passphrase);
//int open_disk();
int close_disk(const char* device_name);
int remove_luks();
int open_disk_by_passphrase(const char* device_name, const char* passphrase);


// utilities / helper functions
int is_device_valid(const char* device);
int convert_key_bin(char *key, const uint8_t *hex, unsigned int size);
void crypt_error_msg(int encryption_result, const char* error_message);
bool is_disk_formatted(const char* device);
void generate_linux_rng_key(const char* key_path);

#endif // disk_encryption_h



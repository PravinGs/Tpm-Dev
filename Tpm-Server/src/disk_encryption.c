#include "disk_encryption.h"

int key_slot = 7;

enum { OFFSET_1M = 2048 , OFFSET_2M = 4096, OFFSET_4M = 8192, OFFSET_8M = 16384 };

void generate_linux_rng_key(const char* key_path) // To generate 256 bit key as a volume key disk encryption
{
    FILE *file = NULL;
    uint32_t buffer[32];
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0)
    {
        printf("Error opening /dev/urandom\n");
        return;
    }

    size_t buffer_size = read(urandom_fd, buffer, sizeof(buffer));

    if ((int)buffer_size < 0)
    {
        printf("Error opening /dev/urandom\n");
        return;
    }

    if (close(urandom_fd) < 0)
    {
        printf("Error closing /dev/urandom\n");
        return;
    }

    file = fopen(key_path, "wb");

    if (file == NULL)
    {
        printf("Invalid Key file.\n");
        return;
    }

    size_t bytes_written = fwrite(buffer, 1, sizeof(buffer), file);
    if (bytes_written != sizeof(buffer))
    {
        printf("Error writing keyfile.\n");
        return;
    }
    fclose(file);

}

int format_disk(const char* device_name, const char* passphrase)
{
    printf("Device Name : %s\n", device_name);
    int encryption_result = 0;
    FILE *file = NULL;
    char *key_path = "/etc/zkey/repository";
    size_t key_size;
    struct crypt_device *crypt_device_ = NULL;
    struct crypt_params_luks1 params = {
		.hash = "sha256",
		.data_alignment = 0,
		.data_device = NULL
    };
    generate_linux_rng_key(key_path);
    char key[KEY_SIZE];
    uint8_t vk_hex[64];
    
    file = fopen(key_path, "rb");
    if (file == NULL)
    {
        printf("Invalid volume key.\n");
        return 1;
    }
    key_size = fread(vk_hex, sizeof(uint8_t), sizeof(vk_hex), file);
    key_size = key_size / 2;
    convert_key_bin(key, vk_hex, key_size);
    encryption_result = is_device_valid(device_name);
    if (encryption_result < 0)
    {
        printf("Invalid Device Path.\n");
        return encryption_result;
    }
    encryption_result = crypt_init(&crypt_device_, device_name);
    if (encryption_result < 0)
    {
        const char* error_message = "crypt_init process failed";
        crypt_error_msg(encryption_result, error_message);
        return encryption_result;
    }
    printf("Crypt setup done.\n");
    encryption_result = crypt_set_data_offset(crypt_device_, OFFSET_8M);
    if (encryption_result < 0)
    {
        const char* error_message = "crypt_set_data_offset process failed";
        crypt_error_msg(encryption_result, error_message);
        return encryption_result;
    }
    printf("Crypt set data offset done.\n");
    encryption_result = crypt_format(crypt_device_, CRYPT_LUKS1, CIPHER, CIPHER_MODE, NULL, key, key_size, &params);

    if (encryption_result < 0)
    {
        const char* error_message = "crypt_format process failed";
        crypt_error_msg(encryption_result, error_message);
        return encryption_result;
    }

    encryption_result = crypt_keyslot_add_by_volume_key(crypt_device_, key_slot, key, key_size, passphrase, strlen(passphrase));

    if (encryption_result != key_slot)
    {
        printf("crypt_keyslot_add_by_volume_key failed : %d\n", encryption_result);
        return encryption_result;
    }

    printf("disk format done.\n");
    uint64_t offset_status = crypt_get_data_offset(crypt_device_);
    printf("Off set status : %ld\n", offset_status);
    crypt_free(crypt_device_);
    return 0;
}

int open_disk_by_passphrase(const char* device_name, const char* passphrase)
{
    int encryption_result = 0;
    struct crypt_device *crypt_device_ = NULL;
    const char *ENCRYPTED_DEVICE_NAME = "encrypted_disk";

    encryption_result = is_device_valid(device_name);
    if (encryption_result < 0)
    {
        printf("Invalid Device Path.\n");
        return encryption_result;
    }

    encryption_result = crypt_init(&crypt_device_, device_name);
    if (encryption_result < 0)
    {
        const char* error_message = "crypt_init process failed";
        crypt_error_msg(encryption_result, error_message);
        return encryption_result;
    }
    printf("Setup Done.\n");

    encryption_result = crypt_load(crypt_device_, CRYPT_LUKS1, NULL);

    if (encryption_result < 0)
    {
        const char* error_message = "crypt_load process failed";
        crypt_error_msg(encryption_result, error_message);
        return encryption_result;
    }  
    printf("crypt load done.\n");

    encryption_result = crypt_activate_by_passphrase(crypt_device_, ENCRYPTED_DEVICE_NAME, CRYPT_ANY_SLOT, passphrase, 		 strlen(passphrase), 0);

    if (encryption_result != key_slot)
    {
        printf("crypt_activate_by_passphrase failed : %d\n", encryption_result);
        return encryption_result;
    }
    printf("Device opened successfully\n");
    system("mkfs.ext4 /dev/mapper/encrypted_disk");
    system("mount /dev/mapper/encrypted_disk /mnt/encrypted_disk");
    crypt_free(crypt_device_);
    return 0;
}

int close_disk(const char* device_name)
{
    int encryption_result = 0;
    struct crypt_device *crypt_device_ = NULL;
    const char *ENCRYPTED_DEVICE_NAME = "encrypted_disk";
    encryption_result = is_device_valid(device_name);
    if (encryption_result < 0) return 1;

    encryption_result = crypt_init(&crypt_device_, device_name);

    if (encryption_result < 0)
    {
        char* error_message = "crypt_init process failed";
        crypt_error_msg(encryption_result, error_message);
        return 1;
    }
    printf("Setup Done.\n");

    system("sync");
    system("umount /mnt/encrypted_disk");

    encryption_result = crypt_deactivate(crypt_device_, ENCRYPTED_DEVICE_NAME);

    if (encryption_result < 0)
    {
        char* error_message = NULL;
        switch(encryption_result)
        {
            case -19:
                strcpy(error_message, "Device Already in a closed state.");
                break;
            default:
                strcpy(error_message, "crypt_deactivate process failed.");
        }
        crypt_error_msg(encryption_result, error_message);
        return 1;
    }
    printf("device closed\n.");
    crypt_free(crypt_device_);
    return 0;

}

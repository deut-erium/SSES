#ifndef SIGNATURE_UTILS_H
#define SIGNATURE_UTILS_H

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#define MAX_SIGNATURE_LEN                       2048
#define MAX_FILE_LEN                            (1024 * 1024)

#define ERR_EXTRACT_PUBKEY_READ                 -1
#define ERR_EXTRACT_PUBKEY_PARSE                -2
#define ERR_EXTRACT_PUBKEY_PUBLICKEY            -3

#define ERR_DECODE_SIGN_BIO_NEW                 -4
#define ERR_DECODE_SIGN_FAILURE                 -5

#define ERR_VERIFY_SIGN_CTX_CREATE              -6
#define ERR_VERIFY_SIGN_INIT_VERIFY             -7
#define ERR_VERIFY_SIGN_VERIFY_UPDATE           -8
#define ERR_VERIFY_SIGN_FAILURE                 -9

#define ERR_EXTRACT_SIGN_FILE_FOPEN             -10
#define ERR_EXTRACT_SIGN_FILE_READ              -11
#define ERR_EXTRACT_SIGN_FILE_MISSING_COMMENT   -12
#define ERR_EXTRACT_SIGN_FILE_MISSING_SIGNATURE -13
#define ERR_EXTRACT_SIGN_FILE_B64DECODE_FAIL    -14
#define ERR_EXTRACT_SIGN_FILE_CONTENT_FAIL      -15

#define ERR_EXTRACT_SIGN_INPLACE_MISSING_COMMENT -16
#define ERR_EXTRACT_SIGN_INPLACE_B64DECODE_FAIL  -17

#define ERR_GET_PUBKEY_LIST_OPENDIR              -18
#define ERR_GET_PUBKEY_LIST_MALLOC               -19

#define ERR_GET_PUBKEYS_PATH_DIR_FAIL            -20
#define ERR_GET_PUBKEYS_PATH_NO_PUBKEYS          -21

typedef struct pubkey_list
{
    char *name;
    EVP_PKEY *pubkey;
} pubkey_list_t;

int is_directory(const char *path);

int get_pubkey_list(const char *directory, 
                    pubkey_list_t ** list,
                    int *list_len);

void free_pubkey_list(pubkey_list_t * list, int list_len);

int get_pubkeys(const char *path, 
                pubkey_list_t ** pubkeys, 
                int *num_pubkeys);

void print_hex(const void *buffer, size_t size);

void print_public_modulus(EVP_PKEY * pkey);

int check_certificate_extension(X509 * cert);

int extract_public_key_from_crt(const char *crt_path, 
                                EVP_PKEY ** public_key);

int decode_signature(char *signature_base64,
                     size_t base64_len,
                     unsigned char **decoded_signature, size_t *signature_len);

int verify_signature(unsigned char *signature_buffer,
                     int signature_length,
                     unsigned char *file_content_buffer,
                     int file_buffer_length, EVP_PKEY * pubkey);

int extract_signature_from_file(const char *filename,
                                unsigned char *signature_buffer,
                                unsigned char *file_content_buffer,
                                size_t *signature_len,
                                size_t *file_content_len);

int extract_signature_inplace(char *buffer,
                              char **signature_buffer,
                              char **file_content_buffer,
                              size_t *signature_len, size_t *file_content_len);

#endif // SIGNATURE_UTILS_H

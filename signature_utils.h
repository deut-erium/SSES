#ifndef SIGNATURE_UTILS_H
#define SIGNATURE_UTILS_H

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#define MAX_SIGNATURE_LEN 2048
#define MAX_FILE_LEN      (4 * 1024 * 1024)
void print_hex(const void *buffer, size_t size);

void print_public_modulus(EVP_PKEY * pkey);

int check_certificate_extension(X509 *cert);

int extract_public_key_from_crt(const char *crt_path, EVP_PKEY ** public_key);

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
                      size_t *signature_len, size_t *file_content_len);

int extract_signature_inplace(char * buffer,
                    char ** signature_buffer,
                    char ** file_content_buffer,
                    size_t *signature_len,
                    size_t *file_content_len);

#endif // SIGNATURE_UTILS_H

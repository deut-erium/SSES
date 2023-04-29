#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "signature_utils.h"

void print_hex(const void *buffer, size_t size)
{
    const unsigned char *p = buffer;
    for (size_t i = 0; i < size; i++)
    {
        printf("%02x ", p[i]);
    }
    printf("\n");
}

void print_public_modulus(EVP_PKEY * pkey)
{
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL)
    {
        printf("Error: Unable to extract RSA key from public key\n");
        return;
    }

    RSA_print_fp(stdout, rsa, 0);

    RSA_free(rsa);
}


int extract_public_key_from_crt(const char *crt_path, EVP_PKEY ** public_key)
{
    X509 *x509 = NULL;
    BIO *bio = NULL;
    int error = 0;
    // Read certificate file
    bio = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bio, crt_path))
    {
        fprintf(stderr, "Error reading certificate file\n");
        error = ERR_EXTRACT_PUBKEY_READ;
        goto cleanup;
    }

    // Parse certificate
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (x509 == NULL)
    {
        fprintf(stderr, "Error parsing certificate: %s\n", crt_path);
        error = ERR_EXTRACT_PUBKEY_PARSE;
        goto cleanup;
    }

    // Extract public key from certificate
    *public_key = X509_get_pubkey(x509);
    if (*public_key == NULL)
    {
        fprintf(stderr, "Error extracting public key from certificate\n");
        error = ERR_EXTRACT_PUBKEY_PUBLICKEY;
        goto cleanup;
    }
  cleanup:
    if (bio)
        BIO_free(bio);
    if (x509)
        X509_free(x509);
    return error;
}


int decode_signature(char *signature_base64,
                     size_t base64_len,
                     unsigned char **decoded_signature, size_t *signature_len)
{
    int ret = ERR_DECODE_SIGN_FAILURE;
    BIO *b64 = NULL;
    BIO *mem = NULL;
    size_t len;

    if (signature_base64 == NULL)
    {
        fprintf(stderr, "Error: got NULL pointer for base64 signature buffer\n");
        goto out;
    }

    if (decoded_signature == NULL)
    {
        fprintf(stderr, "Error: got NULL pointer for decoded_signature buffer \n");
        goto out;
    }

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL)
    {
        fprintf(stderr, "Error: failed to create BIO\n");
        ret = ERR_DECODE_SIGN_BIO_NEW;
        goto out;
    }

    mem = BIO_new_mem_buf(signature_base64, base64_len);
    if (mem == NULL)
    {
        fprintf(stderr, "Error: failed to create memory buffer BIO\n");
        BIO_free_all(b64);
        ret = ERR_DECODE_SIGN_BIO_NEW;
        goto out;
    }

    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(mem, BIO_CLOSE);

    len = BIO_read(mem, *decoded_signature, base64_len);
    if (len == 0)
    {
        fprintf(stderr, "Error: failed to base64 decode signature\n");
        ret = ERR_DECODE_SIGN_FAILURE;
        goto out_free_mem;
    }

    *signature_len = len;
    ret = 0;


  out_free_mem:
    BIO_free_all(mem);

  out:
    return ret;
}

int verify_signature(unsigned char *signature_buffer,
                     int signature_length,
                     unsigned char *file_content_buffer,
                     int file_buffer_length, EVP_PKEY * pubkey)
{
    int status = 0;
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = EVP_sha256();
    int verify_result;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        return ERR_VERIFY_SIGN_CTX_CREATE;
    }

    if (EVP_VerifyInit(mdctx, md) != 1)
    {
        fprintf(stderr, "Error initializing EVP_VerifyInit\n");
        status = ERR_VERIFY_SIGN_INIT_VERIFY;
        goto cleanup;
    }

    if (EVP_VerifyUpdate(mdctx, file_content_buffer, file_buffer_length) != 1)
    {
        fprintf(stderr, "Error updating EVP_VerifyUpdate\n");
        status = ERR_VERIFY_SIGN_VERIFY_UPDATE;
        goto cleanup;
    }

    verify_result =
        EVP_VerifyFinal(mdctx, signature_buffer, signature_length, pubkey);

    if (verify_result != 1)
    {
        /* fprintf(stderr, "Error verifying signature\n"); */
        status = ERR_VERIFY_SIGN_FAILURE;
        goto cleanup;
    }

  cleanup:
    if (mdctx)
    {
        EVP_MD_CTX_free(mdctx);
    }
    return status;
}

int extract_signature_from_file(const char *filename,
                                unsigned char *signature_buffer,
                                unsigned char *file_content_buffer,
                                size_t *signature_len,
                                size_t *file_content_len)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        return ERR_EXTRACT_SIGN_FILE_FOPEN;
    }
    char line[MAX_SIGNATURE_LEN + 1];
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        fclose(fp);
        return ERR_EXTRACT_SIGN_FILE_READ;
    }

    if (line[0] != '#')
    {
        fclose(fp);
        /* file format 
         * #<base64encoded signature> 
         * #!/bin/bash
         * <SCRIPT CONTENT> 
         * <SCRIPT CONTENT> */
        return ERR_EXTRACT_SIGN_FILE_MISSING_COMMENT;
    }

    size_t line_len = strlen(line);
    if (line_len <= 1)
    {
        fclose(fp);
        return ERR_EXTRACT_SIGN_FILE_MISSING_SIGNATURE; // Error: signature
                                                        // not found
    }
    line[line_len - 1] = '\0';  // Remove the newline character at the end
    char *signature_base64 = line + 1;  // Skip the '#' symbol
    size_t signature_base64_len = strlen(signature_base64);

    size_t decoded_len;
    unsigned char *decoded_signature =
        malloc((signature_base64_len * 3) / 4 + 1);
    if (decode_signature
        (signature_base64, signature_base64_len, &decoded_signature,
         &decoded_len) != 0)
    {
        free(decoded_signature);
        fclose(fp);
        return ERR_EXTRACT_SIGN_FILE_B64DECODE_FAIL;
    }

    memcpy(signature_buffer, decoded_signature, decoded_len);
    *signature_len = decoded_len;

    size_t content_len = 0;
    while (!feof(fp) && content_len < MAX_FILE_LEN)
    {
        size_t read_len = fread(file_content_buffer + content_len, 1,
                                MAX_FILE_LEN - content_len, fp);
        if (read_len == 0 && ferror(fp))
        {
            fclose(fp);
            return ERR_EXTRACT_SIGN_FILE_CONTENT_FAIL;
        }
        content_len += read_len;
    }
    file_content_buffer[content_len] = '\0';
    *file_content_len = content_len;

    fclose(fp);

    return 0;                   // Success
}

int extract_signature_inplace(char *buffer,
                              char **signature_buffer,
                              char **file_content_buffer,
                              size_t *signature_len, size_t *file_content_len)
{
    if (buffer == NULL)
    {
        fprintf(stderr, "Error: NULL buffer encountered to decode signature\n");
        return ERR_EXTRACT_SIGN_INPLACE_B64DECODE_FAIL;
    }
    /* file format 
     * #<base64encoded signature> 
     * #!/bin/bash 
     * <SCRIPT CONTENT>
     * <SCRIPT CONTENT> */
    if (buffer[0] != '#')
    {
        return ERR_EXTRACT_SIGN_INPLACE_MISSING_COMMENT;
    }
    char *newline_pos = strchr(buffer, '\n');
    *signature_buffer = buffer + 1;
    *file_content_buffer = newline_pos + 1;
    *newline_pos = '\0';

    size_t signature_base64_len = strlen(*signature_buffer);

    size_t decoded_len;
    unsigned char *decoded_signature =
        malloc((signature_base64_len * 3) / 4 + 1);
    if (decode_signature
        (*signature_buffer, signature_base64_len, &decoded_signature,
         &decoded_len) != 0)
    {
        free(decoded_signature);
        return ERR_EXTRACT_SIGN_INPLACE_B64DECODE_FAIL;
    }

    memcpy(*signature_buffer, decoded_signature, decoded_len);
    *signature_len = decoded_len;
    (*signature_buffer)[decoded_len] = '\0';

    *file_content_len = strlen(*file_content_buffer);
    free(decoded_signature);
    return 0;                   // Success
}

int is_directory(const char *path)
{
    DIR *dir = opendir(path);
    if (dir)
    {
        closedir(dir);
        return 1;
    }
    else
    {
        return 0;
    }
}


int get_pubkey_list(const char *directory, pubkey_list_t ** list,
                    int *list_len)
{
    if (directory == NULL)
    {
        fprintf(stderr,
                "Error: NULL pointer encountered as directory argument\n");
        return ERR_GET_PUBKEY_LIST_OPENDIR;
    }
    DIR *dir;
    struct dirent *ent;
    pubkey_list_t *files;
    int count = 0;
    int i;

    dir = opendir(directory);
    if (dir == NULL)
    {
        return ERR_GET_PUBKEY_LIST_OPENDIR;
    }

    while ((ent = readdir(dir)) != NULL)
    {
        if (ent->d_type == DT_REG)
        {
            count++;
        }
    }

    files = (pubkey_list_t *) malloc(count * sizeof(pubkey_list_t));
    if (files == NULL)
    {
        return ERR_GET_PUBKEY_LIST_MALLOC;
    }

    rewinddir(dir);

    i = 0;
    while ((ent = readdir(dir)) != NULL)
    {
        if (ent->d_type == DT_REG)
        {
            files[i].name = (char *)malloc(strlen(ent->d_name) + 1);
            if (files[i].name == NULL)
            {
                return ERR_GET_PUBKEY_LIST_MALLOC;  // error allocating memory
            }
            strcpy(files[i].name, ent->d_name);
            char *file_path =
                (char *)malloc(strlen(directory) + strlen(ent->d_name) + 2);
            if (file_path == NULL)
            {
                return ERR_GET_PUBKEY_LIST_MALLOC;  // error allocating memory
            }
            sprintf(file_path, "%s/%s", directory, ent->d_name);
            if (extract_public_key_from_crt(file_path, &files[i].pubkey) >= 0)
            {
                i++;
            }
            free(file_path);
        }
    }
    // realloc non crt files
    files = realloc(files, i * sizeof(pubkey_list_t));

    *list = files;
    *list_len = i;

    closedir(dir);

    return 0;                   // success
}

void free_pubkey_list(pubkey_list_t * list, int list_len)
{
    int i;

    for (i = 0; i < list_len; i++)
    {
        free(list[i].name);
        EVP_PKEY_free(list[i].pubkey);
    }
    free(list);
}


int get_pubkeys(const char *path, pubkey_list_t ** pubkeys, int *num_pubkeys)
{
    if (is_directory(path))
    {
        if (get_pubkey_list(path, pubkeys, num_pubkeys) != 0)
        {
            fprintf(stderr, "Error getting file list\n");
            return ERR_GET_PUBKEYS_PATH_DIR_FAIL;
        }
    }
    else
    {
        *pubkeys = (pubkey_list_t *) malloc(sizeof(pubkey_list_t));
        if (extract_public_key_from_crt(path, &(*pubkeys)[0].pubkey) >= 0)
        {
            *num_pubkeys = 1;
            (*pubkeys)[0].name = (char *)malloc(strlen(path) + 1);
            strcpy((*pubkeys)[0].name, path);
        }
        else
        {
            *num_pubkeys = 0;
        }
    }

    if (*num_pubkeys == 0)
    {
        fprintf(stderr, "no valid pubkeys found\n");
        return ERR_GET_PUBKEYS_PATH_NO_PUBKEYS;
    }

    for (int i = 0; i < *num_pubkeys; i++)
    {
        printf("Loaded certificate %s\n", (*pubkeys)[i].name);
    }
    return 0;
}

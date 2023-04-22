#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define MAX_SIGNATURE_LEN 2048
#define MAX_FILE_LEN      (4 * 1024 * 1024)

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
    if (!rsa)
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
        error = 1;
        goto cleanup;
    }

    // Parse certificate
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!x509)
    {
        fprintf(stderr, "Error parsing certificate\n");
        error = 2;
        goto cleanup;
    }

    // Extract public key from certificate
    *public_key = X509_get_pubkey(x509);
    if (!*public_key)
    {
        fprintf(stderr, "Error extracting public key from certificate\n");
        error = 3;
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
    int ret = -1;
    BIO *b64 = NULL;
    BIO *mem = NULL;
    size_t len;

    b64 = BIO_new(BIO_f_base64());
    if (!b64)
    {
        fprintf(stderr, "Error: failed to create BIO\n");
        goto out;
    }

    mem = BIO_new_mem_buf(signature_base64, base64_len);
    if (!mem)
    {
        fprintf(stderr, "Error: failed to create memory buffer BIO\n");
        BIO_free_all(b64);
        goto out;
    }

    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(mem, BIO_CLOSE);

    len = BIO_read(mem, *decoded_signature, base64_len);
    if (len == 0)
    {
        fprintf(stderr, "Error: failed to base64 decode signature\n");
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
        return 1;               // Error: Could not create EVP_MD_CTX
    }

    if (EVP_VerifyInit(mdctx, md) != 1)
    {
        fprintf(stderr, "Error initializing EVP_VerifyInit\n");
        status = 2;             // Error: Could not initialize EVP_VerifyInit
        goto cleanup;
    }

    if (EVP_VerifyUpdate(mdctx, file_content_buffer, file_buffer_length) != 1)
    {
        fprintf(stderr, "Error updating EVP_VerifyUpdate\n");
        status = 3;             // Error: Could not update EVP_VerifyUpdate
        goto cleanup;
    }

    verify_result =
        EVP_VerifyFinal(mdctx, signature_buffer, signature_length, pubkey);

    if (verify_result != 1)
    {
        fprintf(stderr, "Error verifying signature\n");
        status = 4;             // Error: Could not verify signature
        goto cleanup;
    }

  cleanup:
    if (mdctx)
    {
        EVP_MD_CTX_free(mdctx);
    }
    return status;
}

int extract_signature(const char *filename,
                      unsigned char *signature_buffer,
                      unsigned char *file_content_buffer,
                      size_t *signature_len, size_t *file_content_len)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        return 1;              // Error: unable to open file
    }
    char line[MAX_SIGNATURE_LEN + 1];
    if (fgets(line, sizeof(line), fp) == NULL)
    {
        fclose(fp);
        return 2;              // Error: unable to read file
    }

    if (line[0] != '#')
    {
        fclose(fp);
        return 3;              // Error: invalid file format
    }

    size_t line_len = strlen(line);
    if (line_len <= 1)
    {
        fclose(fp);
        return 4;              // Error: signature not found
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
        return 5;              // Error: unable to decode signature
    }

    memcpy(signature_buffer, decoded_signature, decoded_len);
    *signature_len = decoded_len;

    size_t content_len = 0;
    while (!feof(fp) && content_len < MAX_FILE_LEN)
    {
        size_t read_len =
            fread(file_content_buffer + content_len, 1,
                  MAX_FILE_LEN - content_len, fp);
        if (read_len == 0 && ferror(fp))
        {
            fclose(fp);
            return 6;          // Error: unable to read file
        }
        content_len += read_len;
    }
    file_content_buffer[content_len] = '\0';
    *file_content_len = content_len;

    fclose(fp);

    return 0;                   // Success
}


int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <crt_certificate> <script>\n", argv[0]);
        return 1;
    }
    int ret;
    const char *filename = argv[2];
    unsigned char signature_buffer[MAX_SIGNATURE_LEN];
    unsigned char file_content_buffer[MAX_FILE_LEN];
    size_t signature_len;
    size_t file_content_len;
    int status = extract_signature(filename, signature_buffer, file_content_buffer,
                          &signature_len, &file_content_len);
    if (status != 0)
    {
        fprintf(stderr,
                "Error: unable to extract signature and file contents (status=%d)\n",
                status);
        return 1;
    }
    EVP_PKEY *pubkey = NULL;

    ret = extract_public_key_from_crt(argv[1], &pubkey);
    if (ret)
    {
        fprintf(stderr,
                "Error: unable to extract public key from certificate\n");
        return 1;
    }
    ret = verify_signature((unsigned char *)signature_buffer, signature_len,
                         (unsigned char *)file_content_buffer,
                         file_content_len, pubkey);
    if (ret)
    {
        fprintf(stderr, "Error verifying signature: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(pubkey);
        return 1;
    }

    EVP_PKEY_free(pubkey);
    printf("Signature verified successfully\n");

    return 0;
}

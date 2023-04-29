#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include "unity.h"
#include "../src/message.h"
#include "../src/signature_utils.h"


void test_extract_public_key_from_valid_crt(void)
{
    const char *crt_path = "tests/test_data/valid_certificate.crt";
    EVP_PKEY *public_key = NULL;
    int error = extract_public_key_from_crt(crt_path, &public_key);

    TEST_ASSERT_EQUAL_INT(0, error);
    TEST_ASSERT_NOT_NULL(public_key);

    if (public_key)
        EVP_PKEY_free(public_key);
}

void test_extract_public_key_from_non_existent_crt(void)
{
    const char *crt_path = "tests/test_data/non_existent_certificate.crt";
    EVP_PKEY *public_key = NULL;
    int error = extract_public_key_from_crt(crt_path, &public_key);

    TEST_ASSERT_EQUAL_INT(ERR_EXTRACT_PUBKEY_READ, error);
    TEST_ASSERT_NULL(public_key);
}

void test_extract_public_key_from_invalid_crt(void)
{
    const char *crt_path = "tests/test_data/valid_pubkey.pem";
    EVP_PKEY *public_key = NULL;
    int error = extract_public_key_from_crt(crt_path, &public_key);

    TEST_ASSERT_EQUAL_INT(ERR_EXTRACT_PUBKEY_PARSE, error);
    TEST_ASSERT_NULL(public_key);
}


void test_extract_public_key_from_null_crt_path(void)
{
    const char *crt_path = NULL;
    EVP_PKEY *public_key = NULL;
    int error = extract_public_key_from_crt(crt_path, &public_key);

    TEST_ASSERT_EQUAL_INT(ERR_EXTRACT_PUBKEY_READ, error);
    TEST_ASSERT_NULL(public_key);
}


void test_decode_signature_valid_base64(void)
{
    char *signature_base64 = "c2lnbmF0dXJlX2V4YW1wbGU=";
    size_t base64_len = strlen(signature_base64);
    unsigned char *decoded_signature = malloc(base64_len);
    size_t signature_len;

    int result =
        decode_signature(signature_base64, base64_len, &decoded_signature,
                         &signature_len);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_NOT_NULL(decoded_signature);
    TEST_ASSERT_GREATER_THAN(0, signature_len);
    char *expected_decoded_signature = "signature_example";
    TEST_ASSERT_EQUAL_STRING(expected_decoded_signature,
                             (char *)decoded_signature);
    TEST_ASSERT_EQUAL_INT(signature_len, strlen(expected_decoded_signature));

    free(decoded_signature);
}

void test_decode_signature_invalid_base64(void)
{
    char *signature_base64 = "##??";
    size_t base64_len = strlen(signature_base64);
    unsigned char *decoded_signature = malloc(base64_len);
    size_t signature_len;

    int result =
        decode_signature(signature_base64, base64_len, &decoded_signature,
                         &signature_len);

    TEST_ASSERT_NOT_EQUAL(0, result);

    free(decoded_signature);
}

void test_decode_signature_empty_base64(void)
{
    char *signature_base64 = "";
    size_t base64_len = strlen(signature_base64);
    unsigned char *decoded_signature = malloc(1);
    size_t signature_len = 0;

    int result =
        decode_signature(signature_base64, base64_len, &decoded_signature,
                         &signature_len);
    TEST_ASSERT_NOT_EQUAL(0, result);
    TEST_ASSERT_EQUAL_UINT(0, signature_len);

    free(decoded_signature);
}

void test_decode_signature_null_base64(void)
{
    char *signature_base64 = NULL;
    size_t base64_len = 0;
    unsigned char *decoded_signature = malloc(1);
    size_t signature_len;

    int result =
        decode_signature(signature_base64, base64_len, &decoded_signature,
                         &signature_len);

    TEST_ASSERT_NOT_EQUAL(0, result);

    free(decoded_signature);
}

void test_decode_signature_null_decoded_signature(void)
{
    char *signature_base64 = "c2lnbmF0dXJlX2V4YW1wbGU=";
    size_t base64_len = strlen(signature_base64);
    unsigned char **decoded_signature = NULL;
    size_t signature_len;

    int result =
        decode_signature(signature_base64, base64_len, decoded_signature,
                         &signature_len);

    TEST_ASSERT_NOT_EQUAL(0, result);
}


void test_verify_signature_valid_signature(void)
{
    unsigned char signature_buffer[] = {
        117, 233, 62, 74, 57, 70, 105, 188, 43, 205, 49, 188, 0, 54, 233, 70,
            248, 200, 114, 152, 240, 81, 139, 45, 7, 175, 222, 95, 116, 241,
            126, 177, 164, 72, 82, 39, 44, 13, 103, 220, 204, 2, 204, 47, 105,
            56, 217, 121, 48, 32, 87, 246, 133, 12, 52, 47, 161, 138, 229, 203,
            109, 9, 56, 35, 207, 246, 245, 87, 81, 122, 45, 151, 195, 227, 109,
            156, 180, 18, 113, 215, 239, 21, 193, 133, 6, 76, 126, 208, 65,
            231, 40, 89, 219, 232, 140, 183, 250, 61, 14, 208, 244, 232, 82,
            214, 163, 9, 86, 0, 17, 0, 50, 254, 202, 193, 197, 144, 195, 46,
            16, 172, 158, 231, 219, 152, 219, 93, 65, 80, 153, 124, 242, 134,
            252, 162, 220, 205, 184, 201, 159, 7, 115, 15, 85, 252, 34, 199,
            80, 49, 171, 233, 62, 50, 4, 186, 48, 75, 8, 254, 191, 109, 21, 86,
            163, 170, 182, 6, 218, 215, 3, 237, 138, 172, 63, 94, 162, 131, 36,
            50, 40, 215, 120, 35, 208, 220, 176, 0, 176, 204, 71, 127, 162,
            197, 216, 51, 150, 197, 192, 178, 55, 246, 58, 5, 116, 109, 15, 55,
            86, 213, 18, 242, 50, 80, 156, 142, 222, 3, 118, 215, 40, 248, 48,
            132, 228, 218, 87, 145, 216, 88, 165, 122, 12, 240, 54, 104, 166,
            81, 80, 130, 236, 245, 184, 214, 214, 69, 193, 35, 23, 154, 216,
            239, 77, 197, 193, 106, 160, 222,
    };
    int signature_length = 256;
    unsigned char *file_content_buffer =
        (unsigned char *)"#!/bin/bash\n\necho \"hello world\"\n";
    int file_buffer_length = 32;
    EVP_PKEY *pubkey = NULL;
    const char *crt_path = "tests/test_data/valid_certificate.crt";
    int error = extract_public_key_from_crt(crt_path, &pubkey);

    TEST_ASSERT_EQUAL_INT(0, error);
    TEST_ASSERT_NOT_NULL(pubkey);

    int result = verify_signature(signature_buffer, signature_length,
                                  file_content_buffer, file_buffer_length,
                                  pubkey);

    TEST_ASSERT_EQUAL_INT(0, result);
    if (pubkey)
        EVP_PKEY_free(pubkey);
}


void test_verify_signature_invalid_signature(void)
{
    // 1st byte changed from signature
    unsigned char signature_buffer[] = {
        0, 233, 62, 74, 57, 70, 105, 188, 43, 205, 49, 188, 0, 54, 233, 70,
            248, 200, 114, 152, 240, 81, 139, 45, 7, 175, 222, 95, 116, 241,
            126, 177, 164, 72, 82, 39, 44, 13, 103, 220, 204, 2, 204, 47, 105,
            56, 217, 121, 48, 32, 87, 246, 133, 12, 52, 47, 161, 138, 229, 203,
            109, 9, 56, 35, 207, 246, 245, 87, 81, 122, 45, 151, 195, 227, 109,
            156, 180, 18, 113, 215, 239, 21, 193, 133, 6, 76, 126, 208, 65,
            231, 40, 89, 219, 232, 140, 183, 250, 61, 14, 208, 244, 232, 82,
            214, 163, 9, 86, 0, 17, 0, 50, 254, 202, 193, 197, 144, 195, 46,
            16, 172, 158, 231, 219, 152, 219, 93, 65, 80, 153, 124, 242, 134,
            252, 162, 220, 205, 184, 201, 159, 7, 115, 15, 85, 252, 34, 199,
            80, 49, 171, 233, 62, 50, 4, 186, 48, 75, 8, 254, 191, 109, 21, 86,
            163, 170, 182, 6, 218, 215, 3, 237, 138, 172, 63, 94, 162, 131, 36,
            50, 40, 215, 120, 35, 208, 220, 176, 0, 176, 204, 71, 127, 162,
            197, 216, 51, 150, 197, 192, 178, 55, 246, 58, 5, 116, 109, 15, 55,
            86, 213, 18, 242, 50, 80, 156, 142, 222, 3, 118, 215, 40, 248, 48,
            132, 228, 218, 87, 145, 216, 88, 165, 122, 12, 240, 54, 104, 166,
            81, 80, 130, 236, 245, 184, 214, 214, 69, 193, 35, 23, 154, 216,
            239, 77, 197, 193, 106, 160, 222,
    };
    int signature_length = 256;
    unsigned char *file_content_buffer =
        (unsigned char *)"#!/bin/bash\n\necho \"hello world\"\n";
    int file_buffer_length = 32;

    EVP_PKEY *pubkey = NULL;
    const char *crt_path = "tests/test_data/valid_certificate.crt";
    int error = extract_public_key_from_crt(crt_path, &pubkey);

    TEST_ASSERT_EQUAL_INT(0, error);
    TEST_ASSERT_NOT_NULL(pubkey);

    int result = verify_signature(signature_buffer, signature_length,
                                  file_content_buffer, file_buffer_length,
                                  pubkey);

    TEST_ASSERT_NOT_EQUAL(0, result);
    if (pubkey)
        EVP_PKEY_free(pubkey);
}


void test_verify_signature_valid_signature_incorrect_pubkey(void)
{
    unsigned char signature_buffer[] = {
        117, 233, 62, 74, 57, 70, 105, 188, 43, 205, 49, 188, 0, 54, 233, 70,
            248, 200, 114, 152, 240, 81, 139, 45, 7, 175, 222, 95, 116, 241,
            126, 177, 164, 72, 82, 39, 44, 13, 103, 220, 204, 2, 204, 47, 105,
            56, 217, 121, 48, 32, 87, 246, 133, 12, 52, 47, 161, 138, 229, 203,
            109, 9, 56, 35, 207, 246, 245, 87, 81, 122, 45, 151, 195, 227, 109,
            156, 180, 18, 113, 215, 239, 21, 193, 133, 6, 76, 126, 208, 65,
            231, 40, 89, 219, 232, 140, 183, 250, 61, 14, 208, 244, 232, 82,
            214, 163, 9, 86, 0, 17, 0, 50, 254, 202, 193, 197, 144, 195, 46,
            16, 172, 158, 231, 219, 152, 219, 93, 65, 80, 153, 124, 242, 134,
            252, 162, 220, 205, 184, 201, 159, 7, 115, 15, 85, 252, 34, 199,
            80, 49, 171, 233, 62, 50, 4, 186, 48, 75, 8, 254, 191, 109, 21, 86,
            163, 170, 182, 6, 218, 215, 3, 237, 138, 172, 63, 94, 162, 131, 36,
            50, 40, 215, 120, 35, 208, 220, 176, 0, 176, 204, 71, 127, 162,
            197, 216, 51, 150, 197, 192, 178, 55, 246, 58, 5, 116, 109, 15, 55,
            86, 213, 18, 242, 50, 80, 156, 142, 222, 3, 118, 215, 40, 248, 48,
            132, 228, 218, 87, 145, 216, 88, 165, 122, 12, 240, 54, 104, 166,
            81, 80, 130, 236, 245, 184, 214, 214, 69, 193, 35, 23, 154, 216,
            239, 77, 197, 193, 106, 160, 222,
    };
    int signature_length = 256;
    unsigned char *file_content_buffer =
        (unsigned char *)"#!/bin/bash\n\necho \"hello world\"\n";
    int file_buffer_length = 32;
    EVP_PKEY *pubkey = NULL;
    const char *crt_path = "tests/test_data/valid_certificate2.crt";
    int error = extract_public_key_from_crt(crt_path, &pubkey);

    TEST_ASSERT_EQUAL_INT(0, error);
    TEST_ASSERT_NOT_NULL(pubkey);

    int result = verify_signature(signature_buffer, signature_length,
                                  file_content_buffer, file_buffer_length,
                                  pubkey);

    TEST_ASSERT_NOT_EQUAL(0, result);
    if (pubkey)
        EVP_PKEY_free(pubkey);
}

void test_verify_signature_null_signature_buffer(void)
{
    unsigned char *signature_buffer = NULL;
    int signature_length = 9;
    unsigned char *file_content_buffer =
        (unsigned char *)"#!/bin/bash\n\necho \"hello world\"\n";
    int file_buffer_length = 32;
    EVP_PKEY *pubkey = NULL;
    const char *crt_path = "tests/test_data/valid_certificate.crt";
    int error = extract_public_key_from_crt(crt_path, &pubkey);

    TEST_ASSERT_EQUAL_INT(0, error);
    TEST_ASSERT_NOT_NULL(pubkey);

    int result = verify_signature(signature_buffer, signature_length,
                                  file_content_buffer, file_buffer_length,
                                  pubkey);

    TEST_ASSERT_NOT_EQUAL(0, result);
    if (pubkey)
        EVP_PKEY_free(pubkey);
}

void test_verify_signature_null_filecontent(void)
{
    unsigned char signature_buffer[] = {
        117, 233, 62, 74, 57, 70, 105, 188, 43, 205, 49, 188, 0, 54, 233, 70,
            248, 200, 114, 152, 240, 81, 139, 45, 7, 175, 222, 95, 116, 241,
            126, 177, 164, 72, 82, 39, 44, 13, 103, 220, 204, 2, 204, 47, 105,
            56, 217, 121, 48, 32, 87, 246, 133, 12, 52, 47, 161, 138, 229, 203,
            109, 9, 56, 35, 207, 246, 245, 87, 81, 122, 45, 151, 195, 227, 109,
            156, 180, 18, 113, 215, 239, 21, 193, 133, 6, 76, 126, 208, 65,
            231, 40, 89, 219, 232, 140, 183, 250, 61, 14, 208, 244, 232, 82,
            214, 163, 9, 86, 0, 17, 0, 50, 254, 202, 193, 197, 144, 195, 46,
            16, 172, 158, 231, 219, 152, 219, 93, 65, 80, 153, 124, 242, 134,
            252, 162, 220, 205, 184, 201, 159, 7, 115, 15, 85, 252, 34, 199,
            80, 49, 171, 233, 62, 50, 4, 186, 48, 75, 8, 254, 191, 109, 21, 86,
            163, 170, 182, 6, 218, 215, 3, 237, 138, 172, 63, 94, 162, 131, 36,
            50, 40, 215, 120, 35, 208, 220, 176, 0, 176, 204, 71, 127, 162,
            197, 216, 51, 150, 197, 192, 178, 55, 246, 58, 5, 116, 109, 15, 55,
            86, 213, 18, 242, 50, 80, 156, 142, 222, 3, 118, 215, 40, 248, 48,
            132, 228, 218, 87, 145, 216, 88, 165, 122, 12, 240, 54, 104, 166,
            81, 80, 130, 236, 245, 184, 214, 214, 69, 193, 35, 23, 154, 216,
            239, 77, 197, 193, 106, 160, 222,
    };
    int signature_length = 256;
    unsigned char *file_content_buffer = NULL;
    int file_buffer_length = 0;
    EVP_PKEY *pubkey = NULL;
    const char *crt_path = "tests/test_data/valid_certificate.crt";
    int error = extract_public_key_from_crt(crt_path, &pubkey);

    TEST_ASSERT_EQUAL_INT(0, error);
    TEST_ASSERT_NOT_NULL(pubkey);

    int result = verify_signature(signature_buffer, signature_length,
                                  file_content_buffer, file_buffer_length,
                                  pubkey);

    TEST_ASSERT_NOT_EQUAL(0, result);
    if (pubkey)
        EVP_PKEY_free(pubkey);
}


void test_extract_signature_inplace_valid_buffer(void)
{
    char buffer[] =
        "#c2lnbmF0dXJlX2V4YW1wbGU=\n#!/bin/bash\n<SCRIPT CONTENT>\n<SCRIPT CONTENT>";
    char *signature_buffer;
    char *file_content_buffer;
    size_t signature_len;
    size_t file_content_len;

    int result = extract_signature_inplace(buffer, &signature_buffer,
                                           &file_content_buffer,
                                           &signature_len,
                                           &file_content_len);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_NOT_NULL(signature_buffer);
    TEST_ASSERT_NOT_NULL(file_content_buffer);
    char *expected_decoded_signature = "signature_example";
    TEST_ASSERT_EQUAL_STRING(expected_decoded_signature, signature_buffer);
    TEST_ASSERT_EQUAL_INT(signature_len, strlen(expected_decoded_signature));
    char *expected_file_content =
        "#!/bin/bash\n<SCRIPT CONTENT>\n<SCRIPT CONTENT>";
    TEST_ASSERT_EQUAL_STRING(expected_file_content, file_content_buffer);
    TEST_ASSERT_EQUAL_INT(file_content_len, strlen(expected_file_content));

}

void test_extract_signature_inplace_missing_hash(void)
{
    char buffer[] =
        "c2lnbmF0dXJlX2V4YW1wbGU=\n#!/bin/bash\n<SCRIPT CONTENT>\n<SCRIPT CONTENT>";
    char *signature_buffer;
    char *file_content_buffer;
    size_t signature_len;
    size_t file_content_len;

    int result = extract_signature_inplace(buffer, &signature_buffer,
                                           &file_content_buffer,
                                           &signature_len,
                                           &file_content_len);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_extract_signature_inplace_invalid_base64(void)
{
    char buffer[] = "#!!!=#\n#!/bin/bash\n<SCRIPT CONTENT>\n<SCRIPT CONTENT>";
    char *signature_buffer;
    char *file_content_buffer;
    size_t signature_len;
    size_t file_content_len;

    int result = extract_signature_inplace(buffer, &signature_buffer,
                                           &file_content_buffer,
                                           &signature_len,
                                           &file_content_len);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_extract_signature_inplace_empty_signature(void)
{
    char buffer[] = "#\n#!/bin/bash\n<SCRIPT CONTENT>\n<SCRIPT CONTENT>";
    char *signature_buffer;
    char *file_content_buffer;
    size_t signature_len;
    size_t file_content_len;

    int result = extract_signature_inplace(buffer, &signature_buffer,
                                           &file_content_buffer,
                                           &signature_len,
                                           &file_content_len);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_extract_signature_inplace_missing_newline(void)
{
    char buffer[] =
        "#c2lnbmF0dXJlX2V4YW1wbGU=#!/bin/bash\n<SCRIPT CONTENT>\n<SCRIPT CONTENT>";
    char *signature_buffer;
    char *file_content_buffer;
    size_t signature_len;
    size_t file_content_len;

    int result = extract_signature_inplace(buffer, &signature_buffer,
                                           &file_content_buffer,
                                           &signature_len,
                                           &file_content_len);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_extract_signature_inplace_only_signature(void)
{
    char buffer[] = "#c2lnbmF0dXJlX2V4YW1wbGU=\n";
    char *signature_buffer;
    char *file_content_buffer;
    size_t signature_len;
    size_t file_content_len;

    int result = extract_signature_inplace(buffer, &signature_buffer,
                                           &file_content_buffer,
                                           &signature_len,
                                           &file_content_len);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_NOT_NULL(signature_buffer);
    TEST_ASSERT_NOT_NULL(file_content_buffer);
    TEST_ASSERT_GREATER_THAN(0, signature_len);
    TEST_ASSERT_EQUAL_UINT(0, file_content_len);
}

void test_extract_signature_null_buffer(void)
{
    char *buffer = NULL;
    char *signature_buffer;
    char *file_content_buffer;
    size_t signature_len;
    size_t file_content_len;

    int result = extract_signature_inplace(buffer, &signature_buffer,
                                           &file_content_buffer,
                                           &signature_len,
                                           &file_content_len);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_get_pubkey_list_valid_directory(void)
{
    const char *directory = "tests/test_data";
    pubkey_list_t *list;
    int list_len;

    int result = get_pubkey_list(directory, &list, &list_len);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_NOT_NULL(list);
    TEST_ASSERT_GREATER_THAN(0, list_len);
    free_pubkey_list(list, list_len);
}

void test_get_pubkey_list_empty_directory(void)
{
    const char *directory = "tests/test_data/empty_dir";
    pubkey_list_t *list;
    int list_len;

    int result = get_pubkey_list(directory, &list, &list_len);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_NULL(list);
    TEST_ASSERT_EQUAL_INT(0, list_len);
    free_pubkey_list(list, list_len);
}

void test_get_pubkey_list_null_directory(void)
{
    const char *directory = NULL;
    pubkey_list_t *list;
    int list_len;

    int result = get_pubkey_list(directory, &list, &list_len);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_get_pubkey_list_non_existent_directory(void)
{
    const char *directory = "tests/not_test_data";
    pubkey_list_t *list;
    int list_len;

    int result = get_pubkey_list(directory, &list, &list_len);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

void test_get_pubkeys_valid_directory(void)
{
    const char *directory = "tests/test_data";
    pubkey_list_t *pubkeys;
    int num_pubkeys;

    int result = get_pubkeys(directory, &pubkeys, &num_pubkeys);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_NOT_NULL(pubkeys);
    TEST_ASSERT_GREATER_THAN(0, num_pubkeys);

    free_pubkey_list(pubkeys, num_pubkeys);
}

void test_get_pubkeys_valid_single_certificate(void)
{
    const char *cert_file = "tests/test_data/valid_certificate.crt";
    pubkey_list_t *pubkeys;
    int num_pubkeys;

    int result = get_pubkeys(cert_file, &pubkeys, &num_pubkeys);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_NOT_NULL(pubkeys);
    TEST_ASSERT_EQUAL_INT(1, num_pubkeys);

    free_pubkey_list(pubkeys, num_pubkeys);
}


void test_get_pubkeys_non_existent_path(void)
{
    const char *non_existent_path = "tests/invalid_path";
    pubkey_list_t *pubkeys;
    int num_pubkeys;

    int result = get_pubkeys(non_existent_path, &pubkeys, &num_pubkeys);

    TEST_ASSERT_NOT_EQUAL(0, result);
}


void *start_mock_server(void *client_fd_ptr)
{
    int server_fd;
    struct sockaddr_in server_address;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(3123);
    bind(server_fd, (struct sockaddr *)&server_address,
         sizeof(server_address));
    listen(server_fd, 1);
    struct sockaddr_in client_address;
    socklen_t client_address_length = sizeof(client_address);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_address,
                           &client_address_length);
    *((int *)client_fd_ptr) = client_fd;

    return NULL;
}

int start_mock_client()
{
    int client_fd;
    struct sockaddr_in server_address;
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(3123);
    connect(client_fd, (struct sockaddr *)&server_address,
            sizeof(server_address));

    return client_fd;
}

void create_mock_server_and_client(int *server_fd, int *client_fd)
{
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, start_mock_server, (void *)server_fd);
    *client_fd = start_mock_client();
    /* pthread_join(server_thread, NULL); */
}


void test_valid_communication()
{
    int client_fd, server_fd;
    create_mock_server_and_client(&server_fd, &client_fd);
    char server_buffer[1024 * 1024] = { 0 };
    if ((server_fd == 0) || (client_fd == 0))
    {
        return;
    }

    char *client_data = "data less than 1022 bytes in length";
    int send_success =
        send_data(client_fd, client_data, strlen(client_data), 0);

    TEST_ASSERT_EQUAL_INT(send_success, 0);
    int recieved_bytes = recv_msg(server_fd, server_buffer);

    TEST_ASSERT_EQUAL_INT(recieved_bytes, strlen(client_data));

    int num_bytes = 12313;
    char *somebytes_gt_1022 = malloc(num_bytes);
    send_success = send_data(client_fd, somebytes_gt_1022, num_bytes, 0);
    TEST_ASSERT_EQUAL_INT(send_success, 0);
    memset(server_buffer, 0, sizeof(server_buffer));
    for (int i = 0; i < num_bytes / 1022 + 1; i++)
    {
        int expected_len = i == num_bytes / 1022 ? num_bytes % 1022 : 1022;
        recieved_bytes = recv_msg(server_fd, server_buffer + i * 1022);
        TEST_ASSERT_EQUAL_INT(recieved_bytes, expected_len);
        TEST_ASSERT_EQUAL_STRING_LEN(server_buffer + i * 1022,
                                     somebytes_gt_1022 + i * 1022,
                                     recieved_bytes);
    }

    send_success = send_data(client_fd, somebytes_gt_1022, num_bytes, 1);
    TEST_ASSERT_EQUAL_INT(send_success, 0);
    memset(server_buffer, 0, sizeof(server_buffer));
    for (int i = 0; i < num_bytes / 1022 + 1; i++)
    {
        int expected_len = i == num_bytes / 1022 ? num_bytes % 1022 : 1022;
        recieved_bytes = recv_msg(server_fd, server_buffer + i * 1022);
        TEST_ASSERT_EQUAL_INT(recieved_bytes, expected_len);
        TEST_ASSERT_EQUAL_STRING_LEN(server_buffer + i * 1022,
                                     somebytes_gt_1022 + i * 1022,
                                     recieved_bytes);
    }
    recieved_bytes = recv_msg(server_fd, server_buffer);
    TEST_ASSERT_EQUAL_INT(recieved_bytes, 0);

    free(somebytes_gt_1022);
    close(server_fd);
    close(client_fd);
}

// function to mimic script execution logic in server
int execute_script(char *script, int script_len, char *output_buffer,
                   int *output_len)
{
    char temp_filename[] = "/tmp/temp_script_XXXXXX";
    int temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1)
    {
        perror("Failed to create temporary file");
        return -1;
    }
    write(temp_fd, script, script_len);
    close(temp_fd);

    // Execute the script using 'bash'
    char command[1024];
    snprintf(command, sizeof(command), "bash %s", temp_filename);

    FILE *fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("Failed to execute script");
        remove(temp_filename);
        return -1;
    }

    int numread = 0;
    int total = 0;
    while ((numread = fread(output_buffer + total, 1, 1024, fp)))
    {
        total += numread;
    }
    *output_len = total;

    pclose(fp);
    remove(temp_filename);

    return 0;
}

void test_execute_script_hello_world()
{
    char *script = "echo 'Hello, World!'";
    char *expected_output = "Hello, World!\n";
    int script_len = strlen(script);

    int expected_outputlen = strlen(expected_output);

    char output_buffer[1024 * 1024];
    int output_len = 0;

    int execution_status =
        execute_script(script, script_len, output_buffer, &output_len);
    TEST_ASSERT_EQUAL_INT(execution_status, 0);
    TEST_ASSERT_EQUAL_INT(expected_outputlen, output_len);
    TEST_ASSERT_EQUAL_STRING_LEN(expected_output, output_buffer, output_len);
}

void test_execute_script_simple_forloop()
{
    char *script = "#!/bin/bash\nfor i in {1..3}\ndo\n    echo $i\ndone\n\n";
    char *expected_output = "1\n2\n3\n";
    int script_len = strlen(script);

    int expected_outputlen = strlen(expected_output);

    char output_buffer[1024 * 1024];
    int output_len = 0;

    int execution_status =
        execute_script(script, script_len, output_buffer, &output_len);
    TEST_ASSERT_EQUAL_INT(execution_status, 0);
    TEST_ASSERT_EQUAL_INT(expected_outputlen, output_len);
    TEST_ASSERT_EQUAL_STRING_LEN(expected_output, output_buffer, output_len);
}

void test_execute_script_conditional()
{
    char *script =
        "#!/bin/bash\nif [ 3 -gt 2 ]; then echo 'True'; else echo 'False'; fi\n";
    char *expected_output = "True\n";
    int script_len = strlen(script);

    int expected_outputlen = strlen(expected_output);

    char output_buffer[1024 * 1024];
    int output_len = 0;

    int execution_status =
        execute_script(script, script_len, output_buffer, &output_len);
    TEST_ASSERT_EQUAL_INT(execution_status, 0);
    TEST_ASSERT_EQUAL_INT(expected_outputlen, output_len);
    TEST_ASSERT_EQUAL_STRING_LEN(expected_output, output_buffer, output_len);
}

void test_execute_script_invalid_script()
{
    char *script = "#!/bin/bash\nechoo 'Invalid command'\n";
    char *expected_output = "";
    int script_len = strlen(script);

    int expected_outputlen = strlen(expected_output);

    char output_buffer[1024 * 1024];
    int output_len = 0;

    int execution_status =
        execute_script(script, script_len, output_buffer, &output_len);
    TEST_ASSERT_EQUAL_INT(execution_status, 0);
    TEST_ASSERT_EQUAL_INT(expected_outputlen, output_len);
    TEST_ASSERT_EQUAL_STRING_LEN(expected_output, output_buffer, output_len);
}

void test_execute_script_empty_script()
{
    char *script = "";
    char *expected_output = "";
    int script_len = strlen(script);

    int expected_outputlen = strlen(expected_output);

    char output_buffer[1024 * 1024];
    int output_len = 0;

    int execution_status =
        execute_script(script, script_len, output_buffer, &output_len);
    TEST_ASSERT_EQUAL_INT(execution_status, 0);
    TEST_ASSERT_EQUAL_INT(expected_outputlen, output_len);
    TEST_ASSERT_EQUAL_STRING_LEN(expected_output, output_buffer, output_len);
}

void test_execute_script_command_line_args()
{
    char *script =
        "#!/bin/bash\narg1='Hello'\narg2='World'\necho \"$arg1, $arg2!\"\n";
    char *expected_output = "Hello, World!\n";
    int script_len = strlen(script);

    int expected_outputlen = strlen(expected_output);

    char output_buffer[1024 * 1024];
    int output_len = 0;

    int execution_status =
        execute_script(script, script_len, output_buffer, &output_len);
    TEST_ASSERT_EQUAL_INT(execution_status, 0);
    TEST_ASSERT_EQUAL_INT(expected_outputlen, output_len);
    TEST_ASSERT_EQUAL_STRING_LEN(expected_output, output_buffer, output_len);
}

void test_execute_script_sleep()
{
    char *script = "#!/bin/bash\nsleep 1\necho 'Finished sleeping'\n";
    char *expected_output = "Finished sleeping\n";
    int script_len = strlen(script);

    int expected_outputlen = strlen(expected_output);

    char output_buffer[1024 * 1024];
    int output_len = 0;

    int execution_status =
        execute_script(script, script_len, output_buffer, &output_len);
    TEST_ASSERT_EQUAL_INT(execution_status, 0);
    TEST_ASSERT_EQUAL_INT(expected_outputlen, output_len);
    TEST_ASSERT_EQUAL_STRING_LEN(expected_output, output_buffer, output_len);
}

void setUp(void)
{
}

void tearDown(void)
{
}


int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_extract_public_key_from_valid_crt);
    RUN_TEST(test_extract_public_key_from_non_existent_crt);
    RUN_TEST(test_extract_public_key_from_invalid_crt);
    RUN_TEST(test_extract_public_key_from_null_crt_path);

    RUN_TEST(test_decode_signature_valid_base64);
    RUN_TEST(test_decode_signature_invalid_base64);
    RUN_TEST(test_decode_signature_empty_base64);
    RUN_TEST(test_decode_signature_null_base64);
    RUN_TEST(test_decode_signature_null_decoded_signature);

    RUN_TEST(test_verify_signature_valid_signature);
    RUN_TEST(test_verify_signature_invalid_signature);
    RUN_TEST(test_verify_signature_valid_signature_incorrect_pubkey);
    RUN_TEST(test_verify_signature_null_signature_buffer);
    RUN_TEST(test_verify_signature_null_signature_buffer);

    RUN_TEST(test_extract_signature_inplace_valid_buffer);
    RUN_TEST(test_extract_signature_inplace_missing_hash);
    RUN_TEST(test_extract_signature_inplace_invalid_base64);
    RUN_TEST(test_extract_signature_inplace_empty_signature);
    RUN_TEST(test_extract_signature_inplace_missing_newline);
    RUN_TEST(test_extract_signature_inplace_only_signature);
    RUN_TEST(test_extract_signature_null_buffer);

    RUN_TEST(test_get_pubkey_list_valid_directory);
    RUN_TEST(test_get_pubkey_list_empty_directory);
    RUN_TEST(test_get_pubkey_list_null_directory);
    RUN_TEST(test_get_pubkey_list_non_existent_directory);

    RUN_TEST(test_get_pubkeys_valid_directory);
    RUN_TEST(test_get_pubkeys_valid_single_certificate);
    RUN_TEST(test_get_pubkeys_non_existent_path);

    RUN_TEST(test_valid_communication);

    RUN_TEST(test_execute_script_hello_world);
    RUN_TEST(test_execute_script_simple_forloop);
    RUN_TEST(test_execute_script_conditional);
    RUN_TEST(test_execute_script_invalid_script);
    RUN_TEST(test_execute_script_empty_script);
    RUN_TEST(test_execute_script_command_line_args);
    RUN_TEST(test_execute_script_sleep);

    return UNITY_END();
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "message.h"
#include "signature_utils.h"

#define PORT           8080
#define MAXSCRIPTSIZE (1024 * 1024)

void *handle_client(void *arg);

struct thread_args
{
    int sock;
    pubkey_list_t *pubkey_list;
    int num_pubkeys;
};


int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr,
                "Usage: %s [crt_certificate_path | crt_certificate_directory]\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt
        (server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
         sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    pubkey_list_t *pubkeys = NULL;
    int num_pubkeys = 0;
    if (get_pubkeys(argv[1], &pubkeys, &num_pubkeys) < 0)
    {
        fprintf(stderr,
                "Error: unable to extract public key from certificate\n");
        free_pubkey_list(pubkeys, num_pubkeys);
        exit(EXIT_FAILURE);
    }


    while (1)
    {
        int new_socket;

        if ((new_socket =
             accept(server_fd, (struct sockaddr *)&address,
                    (socklen_t *) & addrlen)) < 0)
        {
            perror("accept");
            sleep(1);           // avoid busy looping
            continue;
        }

        printf("Connection: %d\tNew connection accepted.\n", new_socket);
        struct thread_args args = { new_socket, pubkeys, num_pubkeys };
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void *)&args) < 0)
        {
            perror("could not create thread");
            close(new_socket);
            continue;
        }

        if (pthread_detach(thread_id) < 0)
        {
            perror("could not detach thread");
            close(new_socket);
            continue;
        }
    }
    free_pubkey_list(pubkeys, num_pubkeys);
    return 0;
}


void *handle_client(void *arg)
{
    struct thread_args *arguments = (struct thread_args *)arg;
    int sock = arguments->sock;
    int num_pubkeys = arguments->num_pubkeys;
    pubkey_list_t *pubkeys = arguments->pubkey_list;
    char buffer[1024] = { 0 };
    char signed_script[MAXSCRIPTSIZE] = { 0 };

    // Receive(all) the Bash script from the client in messages
    int signed_script_len = recvall(sock, signed_script, MAXSCRIPTSIZE);
    if (signed_script_len == -1)
    {
        fprintf(stderr, "Connection: %d\tError: read failed\n", sock);
        goto exit;
    }
    else if (signed_script_len == -2)
    {
        fprintf(stderr,
                "Connection: %d\tError: Bash script exceeds 1MB in size.\n",
                sock);
        goto exit;
    }

    char *signature_buffer = NULL;
    char *script = NULL;
    size_t signature_len;
    size_t script_len;
    if (extract_signature_inplace
        (signed_script, &signature_buffer, &script, &signature_len,
         &script_len) < 0)
    {
        char status[] = "Failed to verify signature\n";
        send_data(sock, status, sizeof(status), 1);
        fprintf(stderr, "Connection: %d\tError: signature extraction failed",
                sock);
        goto exit;
    }

    int verified = 0;
    int pubkey_num;
    for (pubkey_num = 0; pubkey_num < num_pubkeys; pubkey_num++)
    {
        if (verify_signature((unsigned char *)signature_buffer,
                             signature_len, (unsigned char *)script,
                             script_len, pubkeys[pubkey_num].pubkey) == 0)
        {
            verified = 1;
            break;
        }
    }
    if (verified)
    {
        printf("Connection: %d\tVerified signature with %s\n", sock,
               pubkeys[pubkey_num].name);
        char status[] = "Signature verification success, executing script\n";
        send_data(sock, status, sizeof(status), 0);
    }

    else
    {
        char status[] = "Failed to verify signature\n";
        send_data(sock, status, sizeof(status), 1);
        printf("Connection: %d\tError: failed to verify the signature\n",
               sock);
        goto exit;
    }

    char temp_filename[] = "/tmp/temp_script_XXXXXX";
    int temp_fd = mkstemp(temp_filename);

    if (temp_fd == -1)
    {
        perror("Failed to create temporary file for script");
        goto removetemp;
    }
    write(temp_fd, script, script_len);
    close(temp_fd);

    char command[1024];
    snprintf(command, sizeof(command), "bash %s", temp_filename);


    // Execute the Bash script from buffer and capture the output
    FILE *fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("popen failed");
        goto removetemp;
    }

    memset(buffer, 0, sizeof(buffer));
    // Send the output of the Bash script back to the client
    int numread = 0;
    while ((numread = fread(buffer, 1, 1024, fp)))
    {
        if (send_data(sock, buffer, numread, 0) < 0)
        {
            perror("send failed");
            goto closefp;
        }
        memset(buffer, 0, sizeof(buffer));
    }

  closefp:
    pclose(fp);

  removetemp:
    remove(temp_filename);

  exit:
    printf("Connection: %d\tClosed\n", sock);
    close(sock);
    pthread_exit(NULL);
}

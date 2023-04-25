#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "message.h"

#define PORT 8080
#define MAXSCRIPTSIZE (1024 * 1024)

void *handle_client(void *arg);

int main() 
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) \
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) 
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

    if (listen(server_fd, 3) < 0) 
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1) 
    {
        printf("Waiting for incoming connections...\n");

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) 
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        printf("New connection accepted.%d\n",new_socket);

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void *)&new_socket) < 0) 
        {
            perror("could not create thread");
            exit(EXIT_FAILURE);
        }

        if (pthread_detach(thread_id) < 0) 
        {
            perror("could not detach thread");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}


void *handle_client(void *arg) 
{
    int sock = *(int *)arg;
    char buffer[1024] = {0};
    char script[MAXSCRIPTSIZE] = {0};

    // Receive(all) the Bash script from the client in messages
    int script_len = recvall(sock, script, MAXSCRIPTSIZE);
    if (script_len == -1)
    {
        fprintf(stderr, "read failed\n");
        close(sock);
        pthread_exit(NULL);
    }
    else if(script_len == -2)
    {
        fprintf(stderr,"Error: Bash script exceeds 1MB in size.\n");
        close(sock);
        pthread_exit(NULL);
    }

    // Execute the Bash script from buffer and capture the output
    FILE *fp = popen(script, "r");
    if (fp == NULL) 
    {
        perror("popen failed");
        close(sock);
        pthread_exit(NULL);
    }
    
    memset(buffer, 0, sizeof(buffer));
    // Send the output of the Bash script back to the client
    int numread=0;
    while ((numread=fread(buffer, 1, 1024, fp))){
        if (send_data(sock, buffer, numread, 0) <0)
        {
            perror("send failed");
            fclose(fp);
            close(sock);
            pthread_exit(NULL);
        }
        memset(buffer, 0, sizeof(buffer));
    }

    fclose(fp);
    close(sock);
    printf("Connection closed.%d\n",sock);

    pthread_exit(NULL);
}



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "message.h"

#define PORT 8080
#define MAXSCRIPTSIZE (1024 * 1024)
#define BUFFERSIZE 1024

int main(int argc, char const *argv[]) 
{
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char buffer[BUFFERSIZE] = {0};
    char script[MAXSCRIPTSIZE] = {0};

    if (argc != 2) 
    {
        printf("Usage: %s <script_path>\n", argv[0]);
        return -1;
    }

    // Open the Bash script file
    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) 
    {
        perror("fopen failed");
        return -2;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    fread(script, fsize, 1, fp);
    fclose(fp);
    script[fsize] = 0; 

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("socket creation failed");
        return -3;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) 
    {
        perror("invalid address");
        return -4;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    {
        perror("connection failed");
        return -5;
    }

    // Send the Bash script to the server
    if (send_data(sock, script, fsize, 1) < 0) 
    {
        perror("send failed");
        return -6;
    }


    memset(buffer, 0, sizeof(buffer));
    // Receive the output of the Bash script from the server
    while ((valread = recv_msg(sock, buffer)) > 0) 
    {
        printf("%s", buffer);
        memset(buffer, 0, sizeof(buffer));
    }

    close(sock);

    return 0;
}
 

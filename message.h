#ifndef MESSAGE_H
#define MESSAGE_H

#include <unistd.h>
#include <sys/socket.h>
#include <string.h>

struct message {
    char data[1022];
    short size;
};

int send_data(int sockfd, const char * data, size_t datalen, int include_termination);

int recv_msg(int sockfd, char * buffer);

int recvall(int sockfd, char * buffer, size_t maxbufsize);

#endif /* MESSAGE_H */

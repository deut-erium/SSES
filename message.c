#include "message.h"

int send_data(int sockfd, const char * data, size_t datalen, int include_termination) 
{
    size_t total_sent = 0;
    while (total_sent < datalen) 
    {
        size_t chunk_size = datalen - total_sent;
        if (chunk_size > 1022) 
        {
            chunk_size = 1022;
        }
        struct message msg = {{0}, (short)chunk_size};
        memcpy(msg.data, data + total_sent, chunk_size);
        ssize_t sent = send(sockfd, &msg, sizeof(struct message), 0);
        if (sent == -1) 
        {
            return -1;  // error occurred
        }
        total_sent += chunk_size;
    }
    if (include_termination) 
    {
        struct message msg = {{0}, 0};
        ssize_t sent = send(sockfd, &msg, sizeof(struct message), 0);
        if (sent == -1) 
        {
            return -1;  // error occurred
        }
    }
    return 0;  // success
}


int recv_msg(int sockfd, char * buffer)
{
    struct message msg = {{0}, 0};
    ssize_t recieved = recv(sockfd, &msg, sizeof(struct message),0);
    if (recieved == -1)
    {
        return -1;
    }
    if (recieved == 0)
    {
        return 0; // EOS
    }
    memcpy(buffer, msg.data, msg.size);
    return msg.size;
}



int recvall(int sockfd, char * buffer, size_t maxbufsize) 
{
    size_t total_received = 0;
    while (1) 
    {
        struct message msg = {{0}, 0};
        ssize_t received = recv(sockfd, &msg, sizeof(struct message), 0);
        if (received == -1) 
        {
            return -1;  // error occurred
        }
        if (received == 0) 
        {
            break;  // end of stream
        }
        if (total_received + msg.size > maxbufsize) 
        {
            return -2;  // buffer too small
        }
        memcpy(buffer + total_received, msg.data, msg.size);
        total_received += msg.size;
        if (msg.size == 0) 
        {
            break;  // end of message
        }
    }
    return total_received;  // success
}

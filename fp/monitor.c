#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

void monitor_chat(const char* server_ip, int server_port, const char* channel) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to the server failed");
        close(sockfd);
        return;
    }

    snprintf(buffer, sizeof(buffer), "MONITOR %s", channel);
    send(sockfd, buffer, strlen(buffer), 0);

    while (1) {
        int bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            break;
        }
        buffer[bytes_received] = '\0';
        printf("%s\n", buffer);
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: ./monitor <SERVER_IP> <SERVER_PORT> <CHANNEL>\n");
        return 1;
    }

    const char* server_ip = argv[1];
    int server_port = atoi(argv[2]);
    const char* channel = argv[3];

    monitor_chat(server_ip, server_port, channel);

    return 0;
}

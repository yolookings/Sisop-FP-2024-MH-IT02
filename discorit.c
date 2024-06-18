#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "bcrypt.h"

#define BUFFER_SIZE 1024

void register_user(int sockfd, const char* username, const char* password) {
    char salt[BCRYPT_HASHSIZE];
    char hashed[BCRYPT_HASHSIZE];

    bcrypt_gensalt(12, salt);
    bcrypt_hashpw(password, salt, hashed);

    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "REGISTER %s %s", username, hashed);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}

void login_user(int sockfd, const char* username, const char* password) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LOGIN %s %s", username, password);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}

void join_channel(int sockfd, const char* username, const char* channel, const char* key) {
    char buffer[BUFFER_SIZE];
    if (key != NULL) {
        snprintf(buffer, sizeof(buffer), "JOIN %s %s %s", username, channel, key);
    } else {
        snprintf(buffer, sizeof(buffer), "JOIN %s %s", username, channel);
    }

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}

void list_channels(int sockfd, const char* username) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LIST CHANNEL %s", username);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}

void list_rooms(int sockfd, const char* username, const char* channel) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LIST ROOM %s %s", username, channel);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}

void list_users(int sockfd, const char* username, const char* channel) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LIST USER %s %s", username, channel);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}

void chat(int sockfd, const char* username, const char* channel, const char* message) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "CHAT %s %s %s", username, channel, message);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}

void edit_profile_self(int sockfd, const char* username, const char* new_username, const char* new_password) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "EDIT PROFILE SELF %s %s %s", username, new_username, new_password);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: ./discorit <SERVER_IP> <SERVER_PORT> <COMMAND> <username> [OPTIONS]\n");
        return 1;
    }

    const char* server_ip = argv[1];
    int server_port = atoi(argv[2]);
    const char* command = argv[3];
    const char* username = argv[4];

    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to the server failed");
        return 1;
    }

    if (strcmp(command, "REGISTER") == 0) {
        const char* password = argv[6];
        register_user(sockfd, username, password);
    } else if (strcmp(command, "LOGIN") == 0) {
        const char* password = argv[6];
        login_user(sockfd, username, password);
    } else if (strcmp(command, "JOIN") == 0) {
        const char* channel = argv[5];
        const char* key = argc > 6 ? argv[6] : NULL;
        join_channel(sockfd, username, channel, key);
    } else if (strcmp(command, "LIST CHANNEL") == 0) {
        list_channels(sockfd, username);
    } else if (strcmp(command, "LIST ROOM") == 0) {
        const char* channel = argv[5];
        list_rooms(sockfd, username, channel);
    } else if (strcmp(command, "LIST USER") == 0) {
        const char* channel = argv[5];
        list_users(sockfd, username, channel);
    } else if (strcmp(command, "CHAT") == 0) {
        const char* channel = argv[5];
        const char* message = argv[6];
        chat(sockfd, username, channel, message);
    } else if (strcmp(command, "EDIT PROFILE SELF") == 0) {
        const char* new_username = argv[5];
        const char* new_password = argv[6];
        edit_profile_self(sockfd, username, new_username, new_password);
    } else {
        printf("Invalid command\n");
    }

    close(sockfd);
    return 0;
}

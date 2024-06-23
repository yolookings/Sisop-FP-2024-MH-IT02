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
    // Generate salt and hash the password
    bcrypt_gensalt(12, salt);
    bcrypt_hashpw(password, salt, hashed);

    // Construct message to send to server
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "REGISTER %s %s", username, hashed);

    // Send message to server
    send(sockfd, buffer, strlen(buffer), 0);
    
    // Receive response from server
    recv(sockfd, buffer, sizeof(buffer), 0);

    // Check server response
    if (strncmp(buffer, "REGISTER_SUCCESS", 16) == 0) {
        printf("%s berhasil register\n", username);
    } else if (strncmp(buffer, "REGISTER_FAILURE", 16) == 0) {
        printf("%s sudah terdaftar\n", username);
    } else {
        printf("Server returned unexpected response: %s\n", buffer);
    }
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
    const char* server_ip = "127.0.0.1"; // Nilai default IP server
    int server_port = 8080; // Nilai default port server
    const char* command = NULL;
    const char* username = NULL;
    const char* password = NULL;

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "s:p:")) != -1) {
        switch (opt) {
            case 's':
                server_ip = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-s server_ip] [-p server_port] COMMAND ...\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected COMMAND after options\n");
        exit(EXIT_FAILURE);
    }

    // Command should be the next argument after options
    command = argv[optind++];
    
    if (optind >= argc) {
        fprintf(stderr, "Expected username after COMMAND\n");
        exit(EXIT_FAILURE);
    }

    // Username should be the next argument after COMMAND
    username = argv[optind++];

    // If command is REGISTER, expect -p and password
    if (strcmp(command, "REGISTER") == 0) {
        if (optind >= argc || strcmp(argv[optind], "-p") != 0) {
            fprintf(stderr, "Expected -p password after username for REGISTER command\n");
            exit(EXIT_FAILURE);
        }
        if (optind + 1 >= argc) {
            fprintf(stderr, "Expected password after -p for REGISTER command\n");
            exit(EXIT_FAILURE);
        }
        password = argv[optind + 1];
        optind += 2; // Skip -p and password arguments
    }

    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Setup server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to the server failed");
        exit(EXIT_FAILURE);
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

    //close socket
    close(sockfd);
    return 0;
}

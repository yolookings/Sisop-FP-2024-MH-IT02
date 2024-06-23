#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "bcrypt.h"

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 100

typedef struct {
    char username[50];
    char hashed_password[BCRYPT_HASHSIZE];
    char role[10];
} User;

User users[MAX_CLIENTS];
int user_count = 0;

void handle_client(int client_sock);
int register_user(const char* username, const char* hashed_password);
int login_user(const char* username, const char* password);
void save_user_to_csv(const char* username, const char* hashed_password, const char* role);

void* client_handler(void* arg) {
    int client_sock = *(int*)arg;
    handle_client(client_sock);
    close(client_sock);
    free(arg);
    pthread_exit(NULL);
}

int main() {
    int server_sock, client_sock, *new_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 10) < 0) {
        perror("Listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    while ((client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_size))) {
        pthread_t client_thread;
        new_sock = malloc(1);
        *new_sock = client_sock;

        if (pthread_create(&client_thread, NULL, client_handler, (void*)new_sock) < 0) {
            perror("Could not create thread");
            free(new_sock);
        }

        pthread_detach(client_thread);
    }

    if (client_sock < 0) {
        perror("Accept failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    close(server_sock);
    return 0;
}

void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE];
    int read_size;

    while ((read_size = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        char* command = strtok(buffer, " ");
        if (strcmp(command, "REGISTER") == 0) {
            char* username = strtok(NULL, " ");
            char* hashed_password = strtok(NULL, " ");
            if (register_user(username, hashed_password)) {
                save_user_to_csv(username, hashed_password, "user");
                send(client_sock, "REGISTER_SUCCESS", strlen("REGISTER_SUCCESS"), 0);
            } else {
                send(client_sock, "REGISTER_FAILURE", strlen("REGISTER_FAILURE"), 0);
            }
        } else if (strcmp(command, "LOGIN") == 0) {
            char* username = strtok(NULL, " ");
            char* password = strtok(NULL, " ");
            if (login_user(username, password)) {
                save_user_to_csv(username, password, "user");
                send(client_sock, "LOGIN_SUCCESS", strlen("LOGIN_SUCCESS"), 0);
            } else {
                send(client_sock, "LOGIN_FAILURE", strlen("LOGIN_FAILURE"), 0);
            }
        } else if (strcmp(command, "JOIN") == 0) {
            // Implement JOIN command handling
            send(client_sock, "JOIN_SUCCESS", strlen("JOIN_SUCCESS"), 0);
        } else if (strcmp(command, "LIST") == 0) {
            // Implement LIST command handling
            send(client_sock, "LIST_RESPONSE", strlen("LIST_RESPONSE"), 0);
        } else if (strcmp(command, "CHAT") == 0) {
            // Implement CHAT command handling
            send(client_sock, "CHAT_SUCCESS", strlen("CHAT_SUCCESS"), 0);
        } else if (strcmp(command, "EDIT") == 0) {
            // Implement EDIT command handling
            send(client_sock, "EDIT_SUCCESS", strlen("EDIT_SUCCESS"), 0);
        } else {
            send(client_sock, "UNKNOWN_COMMAND", strlen("UNKNOWN_COMMAND"), 0);
        }
    }

    if (read_size == 0) {
        printf("Client disconnected\n");
    } else if (read_size == -1) {
        perror("recv failed");
    }
}

int register_user(const char* username, const char* hashed_password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return 0;
        }
    }

    strcpy(users[user_count].username, username);
    strcpy(users[user_count].hashed_password, hashed_password);
    strcpy(users[user_count].role, "user");
    user_count++;
    return 1;
}

int login_user(const char* username, const char* password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            if (bcrypt_checkpw(password, users[i].hashed_password) == 0) {
                return 1;
            }
        }
    }
    
    return 0;
}

void save_user_to_csv(const char* username, const char* hashed_password, const char* role) {
    FILE *fp = fopen("user.csv", "a");
    if (fp == NULL) {
        perror("Could not open user.csv");
        return;
    }
    fprintf(fp, "%s,%s,%s\n", username, hashed_password, role);
    fclose(fp);
}

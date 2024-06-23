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
    int is_root;
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
    if (server_sock < 0) { perror("Socket creation failed"); exit(EXIT_FAILURE); }

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
                send(client_sock, "LOGIN_SUCCESS", strlen("LOGIN_SUCCESS"), 0);
            } else {
                send(client_sock, "LOGIN_FAILURE", strlen("LOGIN_FAILURE"), 0);
            }
        } else if (strcmp(command, "JOIN") == 0) {
            send(client_sock, "JOIN_SUCCESS", strlen("JOIN_SUCCESS"), 0);
        } else if (strcmp(command, "LIST") == 0) {
            if (users[0].is_root == 1) {
                char response[BUFFER_SIZE] = "[root] LIST USER\n";
                for (int i = 0; i < user_count; i++) {
                    strcat(response, users[i].username);
                    strcat(response, " ");
                }
                send(client_sock, response, strlen(response), 0);
            } else {
                send(client_sock, "LIST_FAILURE", strlen("LIST_FAILURE"), 0);
            }
        } else if (strcmp(command, "CHAT") == 0) {
            send(client_sock, "CHAT_SUCCESS", strlen("CHAT_SUCCESS"), 0);
        } else if (strcmp(command, "EDIT") == 0) {
            char* root_command = strtok(NULL, " ");
            if (strcmp(root_command, "WHERE") == 0) {
                char* target_username = strtok(NULL, " ");
                char* option = strtok(NULL, " ");
                
                if (option != NULL && strcmp(option, "-u") == 0) {
                    char* new_username = strtok(NULL, " ");
                    if (new_username != NULL) {
                        if (users[0].is_root == 1) {
                            for (int i = 0; i < user_count; i++) {
                                if (strcmp(users[i].username, target_username) == 0) {
                                    strcpy(users[i].username, new_username);
                                    send(client_sock, "EDIT_SUCCESS", strlen("EDIT_SUCCESS"), 0);
                                    save_user_to_csv(target_username, users[i].hashed_password, users[i].role);
                                    return;
                                }
                            }
                        } else {
                            send(client_sock, "EDIT_FAILURE", strlen("EDIT_FAILURE"), 0);
                        }
                    }
                } else if (option != NULL && strcmp(option, "-p") == 0) {
                    char* new_password = strtok(NULL, " ");
                    if (new_password != NULL) {
                        if (users[0].is_root == 1) {
                            for (int i = 0; i < user_count; i++) {
                                if (strcmp(users[i].username, target_username) == 0) {
                                    bcrypt_hashpw(new_password, users[i].hashed_password);
                                    send(client_sock, "EDIT_SUCCESS", strlen("EDIT_SUCCESS"), 0);
                                    save_user_to_csv(users[i].username, users[i].hashed_password, users[i].role);
                                    return;
                                }
                            }
                        } else {
                            send(client_sock, "EDIT_FAILURE", strlen("EDIT_FAILURE"), 0);
                        }
                    }
                }
            } else {
                send(client_sock, "UNKNOWN_COMMAND", strlen("UNKNOWN_COMMAND"), 0);
            }
        } else if (strcmp(command, "REMOVE") == 0) {
            char* target_username = strtok(NULL, " ");
            if (users[0].is_root == 1) {
                for (int i = 0; i < user_count; i++) {
                    if (strcmp(users[i].username, target_username) == 0) {
                        for (int j = i; j < user_count - 1; j++) {
                            strcpy(users[j].username, users[j + 1].username);
                            strcpy(users[j].hashed_password, users[j + 1].hashed_password);
                            strcpy(users[j].role, users[j + 1].role);
                            users[j].is_root = users[j + 1].is_root;
                        }
                        user_count--;
                        send(client_sock, "REMOVE_SUCCESS", strlen("REMOVE_SUCCESS"), 0);
                        save_user_to_csv(target_username, "", "");
                        return;
                    }
                }
                send(client_sock, "REMOVE_FAILURE", strlen("REMOVE_FAILURE"), 0);
            } else {
                send(client_sock, "REMOVE_FAILURE", strlen("REMOVE_FAILURE"), 0);
            }
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
    if (user_count == 0) {
        strcpy(users[user_count].role, "root");
        users[user_count].is_root = 1;
    } else {
        strcpy(users[user_count].role, "user");
        users[user_count].is_root = 0;
    }

    strcpy(users[user_count].username, username);
    strcpy(users[user_count].hashed_password, hashed_password);
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
    if (fp == NULL) { perror("Could not open user.csv"); return; }
    fprintf(fp, "%s,%s,%s\n", username, hashed_password, role);
    fclose(fp);
}

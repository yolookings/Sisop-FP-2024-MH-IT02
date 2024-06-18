#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "bcrypt.h"

#define BUFFER_SIZE 1024
#define PORT 8080

void handle_register(int client_sock, char* username, char* hashed_password) {
    FILE *file = fopen("users.csv", "a");
    if (!file) {
        perror("Failed to open users.csv");
        return;
    }

    fprintf(file, "%s,%s,USER\n", username, hashed_password);
    fclose(file);

    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "%s berhasil register", username);
    send(client_sock, response, strlen(response), 0);
}

void handle_login(int client_sock, char* username, char* password) {
    char line[256];
    char stored_username[50];
    char stored_password[BCRYPT_HASHSIZE];
    char role[10];

    FILE *file = fopen("users.csv", "r");
    if (!file) {
        perror("Failed to open users.csv");
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%[^,],%[^,],%s", stored_username, stored_password, role);

        if (strcmp(stored_username, username) == 0) {
            if (bcrypt_checkpw(password, stored_password) == 0) {
                char response[BUFFER_SIZE];
                snprintf(response, sizeof(response), "%s berhasil login", username);
                send(client_sock, response, strlen(response), 0);
                fclose(file);
                return;
            }
        }
    }

    fclose(file);
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Login gagal");
    send(client_sock, response, strlen(response), 0);
}

void handle_join(int client_sock, char* username, char* channel, char* key) {
    char buffer[BUFFER_SIZE];
    if (key != NULL) {
        snprintf(buffer, sizeof(buffer), "JOIN %s %s %s", username, channel, key);
    } else {
        snprintf(buffer, sizeof(buffer), "JOIN %s %s", username, channel);
    }

    // Simpan log join channel di sini (contohnya)

    snprintf(buffer, sizeof(buffer), "%s bergabung ke channel %s", username, channel);
    send(client_sock, buffer, strlen(buffer), 0);
}

void handle_list_channels(int client_sock, char* username) {
    FILE *file = fopen("channels.csv", "r");
    if (!file) {
        perror("Failed to open channels.csv");
        return;
    }

    char buffer[BUFFER_SIZE];
    buffer[0] = '\0';

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char id_channel[10], channel[50], key[50];
        sscanf(line, "%[^,],%[^,],%s", id_channel, channel, key);
        strcat(buffer, channel);
        strcat(buffer, " ");
    }

    fclose(file);
    send(client_sock, buffer, strlen(buffer), 0);
}

void handle_list_rooms(int client_sock, char* channel) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "%s/rooms.csv", channel);

    FILE *file = fopen(buffer, "r");
    if (!file) {
        perror("Failed to open rooms.csv");
        return;
    }

    buffer[0] = '\0';
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char room[50];
        sscanf(line, "%s", room);
        strcat(buffer, room);
        strcat(buffer, " ");
    }

    fclose(file);
    send(client_sock, buffer, strlen(buffer), 0);
}

void handle_list_users(int client_sock, char* channel) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "%s/admin/auth.csv", channel);

    FILE *file = fopen(buffer, "r");
    if (!file) {
        perror("Failed to open auth.csv");
        return;
    }

    buffer[0] = '\0';
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char id_user[10], name[50], role[10];
        sscanf(line, "%[^,],%[^,],%s", id_user, name, role);
        strcat(buffer, name);
        strcat(buffer, " ");
    }

    fclose(file);
    send(client_sock, buffer, strlen(buffer), 0);
}

void handle_chat(int client_sock, char* username, char* channel, char* message) {
    char filename[BUFFER_SIZE];
    snprintf(filename, sizeof(filename), "%s/chat.log", channel);

    FILE *file = fopen(filename, "a");
    if (!file) {
        perror("Failed to open chat log");
        return;
    }

    fprintf(file, "%s: %s\n", username, message);
    fclose(file);

    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "%s: %s", username, message);
    send(client_sock, response, strlen(response), 0);
}

void handle_edit_profile_self(int client_sock, char* username, char* new_username, char* new_password) {
    char line[256];
    char stored_username[50], stored_password[BCRYPT_HASHSIZE], role[10];
    int found = 0;

    FILE *file = fopen("users.csv", "r+");
    if (!file) {
        perror("Failed to open users.csv");
        return;
    }

    FILE *temp = fopen("temp.csv", "w");
    if (!temp) {
        perror("Failed to open temp file");
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%[^,],%[^,],%s", stored_username, stored_password, role);

        if (strcmp(stored_username, username) == 0) {
            char salt[BCRYPT_HASHSIZE];
            char hashed[BCRYPT_HASHSIZE];

            bcrypt_gensalt(12, salt);
            bcrypt_hashpw(new_password, salt, hashed);

            fprintf(temp, "%s,%s,%s\n", new_username, hashed, role);
            found = 1;
        } else {
            fprintf(temp, "%s", line);
        }
    }

    fclose(file);
    fclose(temp);

    remove("users.csv");
    rename("temp.csv", "users.csv");

    char response[BUFFER_SIZE];
    if (found) {
        snprintf(response, sizeof(response), "Profile %s berhasil diubah", username);
    } else {
        snprintf(response, sizeof(response), "User %s tidak ditemukan", username);
    }
    send(client_sock, response, strlen(response), 0);
}

void handle_monitor(int client_sock, char* channel) {
    char filename[BUFFER_SIZE];
    snprintf(filename, sizeof(filename), "%s/chat.log", channel);

    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open chat log");
        return;
    }

    char buffer[BUFFER_SIZE];
    while (fgets(buffer, sizeof(buffer), file)) {
        send(client_sock, buffer, strlen(buffer), 0);
    }

    fclose(file);
}


void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_sock, buffer, sizeof(buffer), 0);
    buffer[bytes_received] = '\0';

    char command[20], username[50], arg1[50], arg2[50];
    sscanf(buffer, "%s %s %s %s", command, username, arg1, arg2);

    if (strcmp(command, "REGISTER") == 0) {
        handle_register(client_sock, username, arg1);
    } else if (strcmp(command, "LOGIN") == 0) {
        handle_login(client_sock, username, arg1);
    } else if (strcmp(command, "JOIN") == 0) {
        handle_join(client_sock, username, arg1, arg2);
    } else if (strcmp(command, "LIST CHANNEL") == 0) {
        handle_list_channels(client_sock, username);
    } else if (strcmp(command, "LIST ROOM") == 0) {
        handle_list_rooms(client_sock, arg1);
    } else if (strcmp(command, "LIST USER") == 0) {
        handle_list_users(client_sock, arg1);
    } else if (strcmp(command, "CHAT") == 0) {
        handle_chat(client_sock, username, arg1, arg2);
    } else if (strcmp(command, "EDIT PROFILE SELF") == 0) {
        handle_edit_profile_self(client_sock, username, arg1, arg2);
    } else if (strcmp(command, "MONITOR") == 0) {
        handle_monitor(client_sock, arg1);
    } else {
        snprintf(buffer, sizeof(buffer), "Invalid command");
        send(client_sock, buffer, strlen(buffer), 0);
    }
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        return 1;
    }

    printf("Server is listening on port %d...\n", PORT);

    while (1) {
        addr_len = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("Client accept failed");
            continue;
        }

        handle_client(client_sock);
        close(client_sock);
    }

    close(server_sock);
    return 0;
}

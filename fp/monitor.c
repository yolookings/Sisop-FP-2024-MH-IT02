#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAX_USERNAME 50
#define MAX_CHANNEL 50
#define MAX_ROOM 50
#define MAX_PASSWORD 50
#define MAX_MESSAGE 1024
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080

typedef struct {
    char username[MAX_USERNAME];
    char channel[MAX_CHANNEL];
    char room[MAX_ROOM];
} User;

int sock = 0;
User current_user;

void login() {
    char password[MAX_PASSWORD];
    printf("Enter username: ");
    scanf("%s", current_user.username);
    printf("Enter password: ");
    scanf("%s", password);

    char message[MAX_MESSAGE];
    snprintf(message, sizeof(message), "LOGIN %s -p %s", current_user.username, password);
    send(sock, message, strlen(message), 0);

    char response[MAX_MESSAGE] = {0};
    read(sock, response, MAX_MESSAGE);
    printf("%s\n", response);

    if (strstr(response, "berhasil login") == NULL) {
        exit(1);
    }
}

void *receive_messages(void *arg) {
    char buffer[MAX_MESSAGE] = {0};
    while (1) {
        int valread = read(sock, buffer, MAX_MESSAGE);
        if (valread > 0) {
            printf("%s\n", buffer);
        }
        memset(buffer, 0, sizeof(buffer));
    }
    return NULL;
}

int main() {
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    login();

    printf("Enter channel name: ");
    scanf("%s", current_user.channel);
    printf("Enter room name: ");
    scanf("%s", current_user.room);

    char monitor_request[MAX_MESSAGE];
    snprintf(monitor_request, sizeof(monitor_request), "MONITOR %s -channel %s -room %s", 
             current_user.username, current_user.channel, current_user.room);
    send(sock, monitor_request, strlen(monitor_request), 0);

    pthread_t receive_thread;
    if (pthread_create(&receive_thread, NULL, receive_messages, NULL) != 0) {
        perror("Failed to create receive thread");
        return -1;
    }

    printf("[%s] -channel %s -room %s\n", current_user.username, current_user.channel, current_user.room);
    printf("~isi chat~\n");
    printf("sebelumnya\n");

    char input[MAX_MESSAGE];
    while (1) {
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;  // Remove newline

        if (strcmp(input, "EXIT") == 0) {
            printf("[%s/%s/%s] EXIT\n", current_user.username, current_user.channel, current_user.room);
            printf("[%s] EXIT\n", current_user.username);
            break;
        }
    }

    close(sock);
    return 0;
}

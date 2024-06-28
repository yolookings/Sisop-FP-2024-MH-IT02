# Laporan Hasil Final Praktikum Sistem Operasi 2024 IT02

## Anggota Kelompok IT 02 :

| Nama Lengkap              | NRP        |
| ------------------------- | ---------- |
| Maulana Ahmad Zahiri      | 5027231010 |
| Syela Zeruya Tandi Lalong | 5027231076 |
| Kharisma Fahrun Nisa'     | 5027231086 |

# Daftar Isi

- [Inti Soal](#inti-soal)

- [Penjelasan Kode](#penjelasan-kode)
- [Discorit](#discoritc)
- [server](#serverc)
- [monitor](#monitorc)
- [Dokumentasi](#dokumentasi)

# inti soal

Oke, jadi soal ini minta kita bikin aplikasi chat client-server yang lengkap banget. Berikut poin-poin penting yang harus diimplementasikan:

1. `Registrasi dan Login:`

- User bisa daftar dan login pakai username dan password.
- Data user dicek sama server, kalau benar, bisa login, kalau salah, server kasih tahu errornya.

2. `Interaksi Chat:`

- User bisa kirim pesan, gabung ke channel, dan ruang obrolan (room).
- Pesan dan status interaksi diatur sama client dan server.
- Server harus pastikan setiap perintah yang dikirim oleh client itu valid.

3. `Keamanan:`

- Password user harus dienkripsi pas dikirim dan disimpan.
- Harus ada validasi dan otorisasi yang baik supaya aman.

4. `Fitur Tambahan:`

- Ada fitur ban/unban user, edit profile, dan exit dari aplikasi.
- Admin bisa manage channel dan room (create, edit, delete).

5. `File Struktur:`

- Ada file users.csv, channels.csv, dan beberapa file log dan chat di masing-masing channel dan room.
  Intinya, kita bikin aplikasi chat yang lengkap dan aman, dengan banyak fitur buat user dan admin.

# Penjelasan Kode

Di bawah ini adalah penjelasan singkat untuk masing-masing file utama dalam aplikasi ini: discorit.c (client), server.c, dan monitor.c.

# discorit.c

#### Header

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "bcrypt.h"

#define BUFFER_SIZE 1024
```

Bagian ini merupakan header file yang dibutuhkan, yaitu `stdio.h` untuk fungsi input/output dasar, `stdlib.h` untuk fungsi umum seperti exit, `string.h` untuk fungsi manipulasi string, `unistd.h` untuk fungsi POSIX seperti getopt dan close, `arpa/inet.h` untuk fungsi terkait jaringan seperti inet_addr. Selain itu, ada definisi `BUFFER_SIZE` sebesar 1024 byte

#### Fungsi register_user

```c
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
```

Fungsi `register_user` melakukan registrasi pengguna dengan membuat salt dan hash password menggunakan bcrypt. Kemudian, mengirim pesan ke server dengan format `REGISTER username, hashed_password`. Dan yang terakhir, menerima dan mengecek respons dari server apakah registrasi berhasil atau gagal

Contoh saat menjalankan kode:

```
./discorit REGISTER sisop -p sisop02
./discorit REGISTER sisop -p sisop02
```

hasilnya:

```
sisop berhasil register
sisop sudah terdaftar
```

#### Fungsi login_user

```c
void login_user(int sockfd, const char* username, const char* password) {
    char line[256];
    char stored_username[50];
    char stored_password[BCRYPT_HASHSIZE];
    char role[10];

    FILE *file = fopen("user.csv", "r");
    if (file == NULL) {
        perror("File users.csv tidak dapat dibuka");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%[^,],%[^,],%s", stored_username, stored_password, role);

        if (strcmp(stored_username, username) == 0) {
            if (bcrypt_checkpw(password, stored_password) == 0) {
                printf("%s berhasil login\n", username);
                printf("[%s]\n", username); // Cetak role setelah login berhasil
                fclose(file);
                return;
            }
            else {
                fclose(file);
                printf("Login gagal\n");
                return;
            }
        }
    }

    fclose(file);
    printf("Login gagal\n"); // Cetak jika username tidak ditemukan
}
```

Fungsi `login_user` melakukan login dengan membaca file `user.csv` untuk mendapatkan username, hashed password, dan role. Kemudian, mengecek apakah username yang diberikan ada dalam file. Setelah itu, memverifikasi password menggunakan bcrypt. Jika benar, maka akan mencetak pesan login berhasil dan role pengguna

Contoh saat menjalankan kode:

```sh
./discorit LOGIN sisop -p sisop02
```

hasilnya:

```sh
sisop berhasil login
[sisop] [sisop]
```

#### Fungsi join_channel

```c
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
```

Fungsi `join_channel` mengirim permintaan untuk bergabung dengan channel tertentu ke server. Jika channel membutuhkan key, maka key tersebut disertakan dalam pesan

Contoh saat menjalankan kode:

```sh
[sisop] JOIN sisopit02
```

hasilnya:

```sh
[sisop/sisopit02]
```

#### Fungsi list_channels

```c
void list_channels(int sockfd, const char* username) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LIST CHANNEL %s", username);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}
```

Fungsi `list_channels` mengirim permintaan untuk mendapatkan daftar channel yang tersedia ke server

#### Fungsi list_rooms

```c
void list_rooms(int sockfd, const char* username, const char* channel) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LIST ROOM %s %s", username, channel);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}
```

Fungsi `list_rooms` mengirimkan permintaan untuk mendapatkan daftar room dalam channel tertentu ke server

#### Fungsi list_users

```c
void list_users(int sockfd, const char* username, const char* channel) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LIST USER %s %s", username, channel);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}
```

Fungsi `list_users` mengirim permintaan untuk mendapatkan daftar pengguna dalam channel tertentu ke server

#### Fungsi chat

```c
void chat(int sockfd, const char* username, const char* channel, const char* message) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "CHAT %s %s %s", username, channel, message);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}
```

Fungsi `chat` mengirim pesan ke channel tertentu ke server

#### Fungsi edit_profile_self

```c
void edit_profile_self(int sockfd, const char* username, const char* new_username, const char* new_password) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "EDIT PROFILE SELF %s %s %s", username, new_username, new_password);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}
```

Fungsi `edit_profile_self` mengirim permintaan untuk mengedit profil pengguna ke server.

#### Main

```c
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
```

Dalam fungsi `main` terdapat hal berikut:

1. Mengambil argumen dari command line untuk mendapatkan IP server, port server, dan perintah apa yang ingin dijalankan
2. Membuat socket dan kemudian menghubungkannya ke server
3. Mengeksekusi perintah yang diberikan seperti, `REGISTER`, `LOGIN`, `JOIN`, `LIST CHANNEL`, `LIST ROOM`, `LIST USER`, `CHAT`, dan `EDIT PROFILE SELF` dengan memanggil fungsi yang sesuai
4. Kemudian, yang terakhir adalah menutup socket setelah perintah selesai dijalankan

# server.c

## Overview

ini merupakan implementasi server untuk aplikasi chat berbasis command-line. Server ini dirancang untuk mendukung berbagai operasi seperti registrasi pengguna, manajemen channel, dan pengelolaan pesan. Berikut adalah panduan singkat untuk memahami struktur dan fungsi utama server ini.

## Pustaka dan Definisi

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bcrypt.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>

```

Pustaka dan konstanta penting diimpor dan didefinisikan di bagian ini karena mencakup semua library dari program server yang akan kita perlukan.

## Struktur Data

```c
typedef struct {
    int socket;
    struct sockaddr_in address;
    char logged_in_user[50];
    char logged_in_role[10];
    char logged_in_channel[50];
    char logged_in_room[50];
} client_info;

client_info *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
```

`client_info` digunakan untuk menyimpan informasi klien yang terhubung.

## Deklarasi Fungsi

```c
#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 10240
#define SALT_SIZE 64
#define USERS_FILE "/Users/mwlanaz/desktop/praktikum/praktikum-sisop/uji-fp/fp/DiscorIT/users.csv"
#define CHANNELS_FILE "/Users/mwlanaz/desktop/praktikum/praktikum-sisop/uji-fp/fp/DiscorIT/channels.csv"


void *handle_client(void *arg);
void daemonize();

void register_user(const char *username, const char *password, client_info *client);
void login_user(const char *username, const char *password, client_info *client);

//create
void create_directory(const char *path, client_info *client);
void create_channel(const char *username, const char *channel, const char *key, client_info *client);
void create_room(const char *username, const char *channel, const char *room, client_info *client);

//list
void list_channels(client_info *client);
void list_rooms(const char *channel, client_info *client);
void list_users(const char *channel, client_info *client);

// join and verify
void join_channel(const char *username, const char *channel, client_info *client);
void verify_key(const char *username, const char *channel, const char *key, client_info *client);
void join_room(const char *channel, const char *room, client_info *client);
//chat
void send_chat(const char *username, const char *channel, const char *room, const char *message, client_info *client);
void see_chat(const char *channel, const char *room, client_info *client);
void edit_chat(const char *channel, const char *room, int id_chat, const char *new_text, client_info *client);
// edit
void edit_channel(const char *old_channel, const char *new_channel, client_info *client);
void edit_room(const char *channel, const char *old_room, const char *new_room, client_info *client);
void edit_profile_self(const char *username, const char *new_value, bool is_password, client_info *client);
//delete
void delete_chat(const char *channel, const char *room, int chat_id, client_info *client);
void delete_directory(const char *path);
void delete_channel(const char *channel, client_info *client);
void delete_room(const char *channel, const char *room, client_info *client);
void delete_all_rooms(const char *channel, client_info *client);
// log
void log_activity(const char *channel, const char *message);
```

Berbagai fungsi yang dideklarasikan untuk menangani koneksi klien dan operasi server.

## Fungsi Utama

```c
int main() {
    daemonize();

    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    pthread_t tid;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Gagal membuat socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Gagal bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Gagal listen");
        exit(EXIT_FAILURE);
    }

    printf("Server berjalan sebagai daemon pada port %d\n", PORT);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addr_len)) < 0) {
            perror("Gagal melakukan accept");
            exit(EXIT_FAILURE);
        }

        pthread_t tid;
        client_info *client = (client_info *)malloc(sizeof(client_info));
        client->socket = new_socket;
        client->address = address;
        memset(client->logged_in_user, 0, sizeof(client->logged_in_user));
        memset(client->logged_in_role, 0, sizeof(client->logged_in_role));
        memset(client->logged_in_channel, 0, sizeof(client->logged_in_channel));
        memset(client->logged_in_room, 0, sizeof(client->logged_in_room));

        pthread_create(&tid, NULL, handle_client, (void *)client);
    }

    return 0;
}

```

Fungsi utama untuk mengatur server sebagai daemon dan menangani koneksi masuk.

## Fungsi daemonize

```c
void daemonize() {
    pid_t pid, sid;

    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int log_fd = open("/tmp/server.log", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (log_fd < 0) {
        exit(EXIT_FAILURE);
    }
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
}
```

Mengubah server menjadi daemon, menutup file descriptors, dan mengalihkan log ke file log.

## Handle Client Function

```c
void *handle_client(void *arg) {
    client_info *cli = (client_info *)arg;
    char buffer[BUFFER_SIZE];
    int n;

    while ((n = read(cli->socket, buffer, sizeof(buffer))) > 0) {
        buffer[n] = '\0';
        printf("Pesan dari client: %s\n", buffer);

        char *token = strtok(buffer, " ");
        if (token == NULL) {
            char response[] = "Perintah tidak dikenali";
            if (write(cli->socket, response, strlen(response)) < 0) {
                perror("Gagal mengirim respons ke client");
            }
            continue;
        }
```

Fungsi `handle_client` membaca pesan dari klien dan memproses perintah yang diterima.

## Command List

```sh
sebagaimana yang tertera dalam file server.c , ada berbagia macam fungsi, dengan simpelnya seperti berikut:
```

- **REGISTER**: Mendaftarkan pengguna baru.
- **LOGIN**: Masuk ke akun pengguna.
- **CREATE**: Membuat channel atau room baru.
- **LIST**: Menampilkan daftar channel, room, atau pengguna.
- **JOIN**: Bergabung ke channel atau room.
- **CHAT**: Mengirim pesan dalam room.

## Operasi Lainnya

```c
send_chat(cli->logged_in_user, cli->logged_in_channel, cli->logged_in_room, message, cli);
} else if (strcmp(token, "SEE") == 0) {
    token = strtok(NULL, " ");
    if (token == NULL || strcmp(token, "CHAT") != 0 || strlen(cli->logged_in_channel) == 0 || strlen(cli->logged_in_room) == 0) {
        char response[] = "Format perintah SEE CHAT tidak valid atau anda belum tergabung dalam room";
        if (write(cli->socket, response, strlen(response)) < 0) {
            perror("Gagal mengirim respons ke client");
        }
        continue;
    }
```

- **send_chat**: Mengirim pesan chat dari pengguna terdaftar.
- **SEE**: Menampilkan chat dari channel dan room.
- **EDIT**: Mengedit chat, channel, room, atau profil pengguna.
- **DEL**: Menghapus chat, channel, atau room.

## Log Aktivitas

```c
void log_activity(const char *channel, const char *message) {
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/home/mwlanaz/desktop/praktikum/praktikum-sisop/uji-fp/fp/DiscorIT/%s/admin/user.log", channel);

    FILE *log_file = fopen(log_path, "a+");
    if (!log_file) {
        perror("Gagal membuka file user.log");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char date[30];
    strftime(date, sizeof(date), "%d/%m/%Y %H:%M:%S", t);

    fprintf(log_file, "[%s] %s\n", date, message);
    fclose(log_file);
}
```

Fungsi `log_activity` untuk mencatat aktivitas ke file log di setiap channel.

Fungsi ini menerima dua parameter: channel yang menunjukkan direktori channel untuk menyimpan log, dan message yang merupakan pesan yang akan dicatat dalam format log.
Path file log di-generate menggunakan snprintf sesuai dengan channel yang diberikan.
File log dibuka dengan mode "a+" untuk menambahkan (append) dan membaca (read) jika sudah ada.
Waktu saat ini diambil menggunakan time() dan diubah menjadi format lokal menggunakan localtime() dan strftime() untuk format tanggal yang sesuai.
Pesan dan tanggal dicatat ke dalam file log menggunakan fprintf.
File log ditutup setelah selesai menulis.

## Kesimpulan

Dengan fitur-fitur di atas, Server memungkinkan pengguna untuk berinteraksi dengan sistem melalui berbagai perintah yang dapat dieksekusi secara aman dan efisien.

# monitor.c

implementasi kode :

## Struct Definition

```c
typedef struct {
    char username[MAX_USERNAME];
    char channel[MAX_CHANNEL];
    char room[MAX_ROOM];
} User;

```

`User`: Struktur yang menyimpan informasi pengguna seperti username, channel, dan room.

## Global Variables

```c
int sock = 0;
User current_user;
```

`sock`: Menyimpan deskriptor socket yang digunakan untuk komunikasi dengan server.
`current_user`: Menyimpan informasi pengguna saat ini.

## Function:

`login` :

```c
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
```

- Fungsi ini menangani proses login pengguna.
- Menerima input username dan password dari pengguna.
- Mengirimkan informasi login ke server dan membaca respon dari server.
- Jika login gagal, program akan keluar.

saat program dijalankan:

```sh
Enter username: (user memasukkan username)
Enter password: (user memasukkan password)
LOGIN qurbancare -p qurban123
qurbancare berhasil login
```

Jika login gagal, program akan keluar dan tidak ada output tambahan.

`receive_messages` :

```c
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
```

- Fungsi ini berjalan di thread terpisah untuk menerima pesan dari server secara kontinu.
- Membaca pesan dari server dan mencetaknya ke layar.

`main` :

```c
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
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "EXIT") == 0) {
            printf("[%s/%s/%s] EXIT\n", current_user.username, current_user.channel, current_user.room);
            printf("[%s] EXIT\n", current_user.username);
            break;
        }
    }

    close(sock);
    return 0;
}
```

- Socket Creation and Connection: Membuat socket dan menghubungkan ke server.
- Login: Memanggil fungsi `login` untuk autentikasi pengguna.
- Channel and Room Selection: Meminta pengguna memasukkan nama channel dan room.
- Send Monitor Request: Mengirimkan permintaan monitor ke server.
- Receive Messages Thread: Membuat thread untuk menerima pesan dari server secara asinkron.
- Message Loop: Loop utama untuk membaca input pengguna dan mengirimkan pesan. Keluar jika pengguna mengetik "EXIT".
- Close Socket: Menutup socket saat selesai.

saat menjalankan program :

```sh
Enter username: (user memasukkan username)
Enter password: (user memasukkan password)
LOGIN qurbancare -p qurban123
qurbancare berhasil login
Enter channel name: (user memasukkan nama channel)
Enter room name: (user memasukkan nama room)
[qurbancare] -channel care -room urban
~isi chat~
sebelumnya
[05/06/2024 23:22:12][3][qurbancare] “hallo”
```

Saat menerima pesan dari server:

```sh
[05/06/2024 23:22:12][3][qurbancare] “hallo”
```

Saat pengguna mengetik "EXIT":

```sh
[qurbancare/care/urban] EXIT
[qurbancare] EXIT
```

# Kesimpulan

Kesimpulan
Program `monitor` menampilkan berbagai output tergantung pada langkah-langkah yang diambil oleh pengguna dan respons dari server. Output utama meliputi pesan sukses atau gagal pada tahap pembuatan socket, koneksi ke server, autentikasi pengguna, serta pesan yang diterima dari server selama program berjalan. Dengan menggunakan socket untuk komunikasi dan thread untuk menangani penerimaan pesan asinkron, program ini memastikan bahwa pengguna dapat memonitor chat dengan lancar dan responsif. Penggunaan autentikasi memastikan bahwa hanya pengguna yang sah yang dapat mengakses dan memonitor chat.

## Dokumentasi

Dokumentasi berikut berisi gambar dari contoh program yang telah dijalankan:

- Berikut adalah dokumentasi saat melakukan registrasi
  ![dokum_fp1](https://github.com/yolookings/Sisop-FP-2024-MH-IT02/assets/151950309/2b4cb921-ab54-449f-b15c-f13e53d2e6a6)
- Berikut adalah dokumentasi saat melakukan login
  ![dokum_fp2](https://github.com/yolookings/Sisop-FP-2024-MH-IT02/assets/151950309/fdd3ba84-e1fb-47fd-b9de-e6e307751f42)
- Berikut adalah dokumentasi yang memperlihatkan list channel
  ![dokum_fp4](https://github.com/yolookings/Sisop-FP-2024-MH-IT02/assets/151950309/bb2c81d7-fc01-43f8-8343-0476516143d7)

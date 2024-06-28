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

## inti soal

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

## Penjelasan Kode

Di bawah ini adalah penjelasan singkat untuk masing-masing file utama dalam aplikasi ini: discorit.c (client), server.c, dan monitor.c.

## discorit.c

### Penjelasan Kode

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
Fungsi `register_user` melakukan registrasi pengguna dengan, membuat salt dan hash password menggunakan bcrypt. Kemudian, mengirim pesan ke server dengan format `REGISTER username, hashed_password`. Dan yang terakhir, menerima dan mengecek respons dari server apakah registrasi berhasil atau gagal

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
Fungsi `login_user` melakukan login dengan membaca file `user.csv` untuk mendapatkan username, hashed password, dan role. Kemudian, mengecek apakah username yang diberikan ada dalam file. Setelah itu, memverifikasi password menggunakan bcrypt. Jika benar, cetak pesan login berhasil dan role pengguna

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
Fungsi `join_channel` mengirim permintaan untuk bergabung dengan channel tertentu ke server. Jika channel membutuhkan kunci, maka kunci tersebut disertakan dalam pesan

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

```c
void list_rooms(int sockfd, const char* username, const char* channel) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LIST ROOM %s %s", username, channel);

    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("%s\n", buffer);
}
```
Fungsi `list_rooms` mengirim permintaan untuk mendapatkan daftar room dalam channel tertentu ke server

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
1. Mengambil argument dari command line untuk mendapatkan IP server, port server, dan perintah apa yang ingin dijalankan
2. Membuat socket dan kemudian menghubungkannya ke server
3. Mengeksekusi perintah yang diberikan seperti, `REGISTER`, `LOGIN`, `JOIN`, `LIST CHANNEL`, `LIST ROOM`, `LIST USER`, `CHAT`, dan `EDIT PROFILE SELF` dengan memanggil fungsi yang sesuai
4. Kemudian, yang terakhir adalah menutup socket setelah perintah selesai dijalankan

implementasi kode :

```c

```

saat menjalankan program :

```sh

```

## server.c

implementasi kode :

```c

```

saat menjalankan program :

```sh

```

## monitor.c

implementasi kode :

```c

```

saat menjalankan program :

```sh

```

## Dokumentasi

Dokumentasi berikut berisi gambar dari contoh program yang telah dijalankan:

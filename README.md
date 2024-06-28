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


#### Fungsi `register_user`
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

#### Fungsi `login_user`
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

#### Fungsi `join_channel`
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

implementasi kode :

```c

```

saat menjalankan program :

```sh

```

# server.c

# monitor.c

implementasi kode :

```c

```

saat menjalankan program :

```sh

```

## Dokumentasi

Dokumentasi berikut berisi gambar dari contoh program yang telah dijalankan:

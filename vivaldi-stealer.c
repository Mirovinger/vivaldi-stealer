#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <byteswap.h>

#define SIZE_OF_PAGE_OFFSET             16
#define SIZE_OF_PAGE_HEADER             8
#define COLUMNS_NUMBER_OF_DB            22
#define MIN_COLUMNS_DATATYPE_TABLE_LEN  23

#define LOGIN_COLUMN    3
#define PASSWORD_COLUMN 5
#define URL_COLUMN      7

typedef unsigned char   byte;
typedef unsigned short  word;
typedef unsigned int    dword;

#pragma pack(1)

typedef struct page_header_struct {
    byte page_type;
    word start_of_first_freeblock;
    word cells_num;
    word start_of_cell_content_area;
    byte fragmented_free_bytes_num;
} page_header;

#pragma pack()

void parse_database(byte* mem, dword mem_size);
void parse_record(byte* record_header);
byte varint_to_word(byte* mem, word* decoded_number);
void format_and_print_credentials(byte* login, byte login_len, byte* password, byte password_len, byte* url, byte url_len);

dword main(dword argc, byte *argv[]) {
    byte* db_path = NULL;
    dword fd = 0;
    dword file_size = 0;
    void* mem = NULL;

    if (argc < 2) {
        printf("Usage: %s <login_data_file>\n", argv[0]);
        printf("\t(<login_data_file> is usually '$HOME/.config/vivaldi/Default/Login Data')\n");
        return 0;
    }
   
    db_path = argv[1];

    fd = open(db_path, O_RDONLY);
    if (!fd) {
        printf("Couldn't open the file '%s'. Errno = %d\n", db_path, errno);
        return -1;
    }

    file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) {
        printf("Couldn't get a size of file '%s'. Errno = %d\n", db_path, errno);
        close(fd);
        return -1;
    }

    mem = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == (void*) -1) {
        printf("Couldn't map the file '%s'. Errno = %d\n", db_path, errno);
        close(fd);
        return -1;
    }

    parse_database((byte*) mem, file_size);

    munmap(mem, file_size);
    close(fd);
    return 0;
}

void parse_database(byte* mem, dword mem_size) {
    byte* page = mem;
    dword page_offset = 0;
    word size_of_page = __bswap_16(*(mem + SIZE_OF_PAGE_OFFSET));

    word* cells_offset_table = NULL;
    word number_of_cells = 0;
    word cell_offset = 0;

    byte* record_header = NULL;

    word i;

    // Skip the first page
    while ((page_offset += size_of_page) <= mem_size) {
        page += size_of_page;

        // Check the page is leaf table b-tree page (type 13)
        if (*(page) != 13)
            continue;

        // Get number of cells
        number_of_cells = __bswap_16(((page_header*) page)->cells_num);

        // Parse each record
        cells_offset_table = (word*) (page + sizeof(page_header));
        for (i = 0; i < number_of_cells; i++) {
            // Compute an address of record header
            record_header = page;
            cell_offset = *(cells_offset_table + i);
            cell_offset = __bswap_16(cell_offset);
            record_header += cell_offset;

            parse_record(record_header);
        }
    }
}

void parse_record(byte* record_header) {
    byte* varint_to_decode = record_header;
    byte varint_size = 0;

    word record_len = 0;
    word columns_datatype_table_len = 0;
    word column_datatype = 0;
    byte length_of_columns[COLUMNS_NUMBER_OF_DB];

    byte i;

    byte* login = NULL;
    byte* password = NULL;
    byte* url = NULL;

    // Read 1'st field, the length of record
    varint_size = varint_to_word(varint_to_decode, &record_len);
    varint_to_decode += varint_size;

    // Skip 2'nd field, record id
    varint_to_decode++;

    // Get 3'rd field, the length of the columns datatype table in bytes.
    varint_size = varint_to_word(varint_to_decode, &columns_datatype_table_len);
    varint_to_decode += varint_size;

    // It may be a record we don't search, i.e. from an other table
    if (columns_datatype_table_len < MIN_COLUMNS_DATATYPE_TABLE_LEN) {
        return;
    }

    // Now we have to decode an every entry from 0 to 7 in this table and determine
    // a length of them.
    for (i = 0; i < COLUMNS_NUMBER_OF_DB; i++) {
        varint_size = varint_to_word(varint_to_decode, &column_datatype);
        varint_to_decode += varint_size;

        if (column_datatype == 1) {
            length_of_columns[i] = 1;
        } else if (column_datatype == 6) {
            length_of_columns[i] = 4;
        } else if (column_datatype >= 12 && column_datatype % 2 == 0) {
            length_of_columns[i] = (column_datatype - 12) / 2;
        } else if (column_datatype >= 13 && column_datatype % 2 == 1) {
            length_of_columns[i] = (column_datatype - 13) / 2;
        }
    }

    // After all, read the login (4), password (6) and url (8) fields 
    // and print them
    login = varint_to_decode
            + length_of_columns[0]
            + length_of_columns[1]
            + length_of_columns[2];

    password = login
            + length_of_columns[3]
            + length_of_columns[4];

    url = password
            + length_of_columns[5]
            + length_of_columns[6];

    format_and_print_credentials(   login, 
                                    length_of_columns[LOGIN_COLUMN], 
                                    password, 
                                    length_of_columns[PASSWORD_COLUMN], 
                                    url, 
                                    length_of_columns[URL_COLUMN]);
 
    return;
}

byte varint_to_word(byte* mem, word* decoded_number) {
    if (mem[0] < 0x80) {
        ((byte*) decoded_number)[0] = mem[0];
        ((byte*) decoded_number)[1] = 0;

        return sizeof(byte);
    }

    ((byte*) decoded_number)[0] = mem[1];
    ((byte*) decoded_number)[1] = mem[0];

    return sizeof(word);
}

void format_and_print_credentials(  byte* login, 
                                    byte login_len, 
                                    byte* password, 
                                    byte password_len, 
                                    byte* url, 
                                    byte url_len) {
    void* mem_for_login = NULL;
    void* mem_for_password = NULL;
    void* mem_for_url = NULL;
    static byte record_number = 1;

    mem_for_login = malloc(login_len + 1);
    mem_for_password = malloc(password_len + 1);
    mem_for_url = malloc(url_len + 1);

    if (!mem_for_login || !mem_for_password || !mem_for_url) {
        printf("Couldn't allocate a memory for the results. Errno = %d\n", errno);
        exit(EXIT_FAILURE);
    }

    memcpy(mem_for_login, login, login_len);
    memcpy(mem_for_password, password, password_len);
    memcpy(mem_for_url, url, url_len);

    *(byte*) (mem_for_login + login_len) = 0;
    *(byte*) (mem_for_password + password_len) = 0;
    *(byte*) (mem_for_url + url_len) = 0;

    printf("#%d record:\n", record_number);
    printf("Login: %s\nPassword: %s\nResource: %s\n\n", mem_for_login, mem_for_password, mem_for_url);

    record_number++;

    free(mem_for_url);
    free(mem_for_password);
    free(mem_for_login);
}

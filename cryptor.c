#include <stdio.h>
#include <string.h> // For strlen, memcpy, toupper
#include <stdlib.h> // For malloc, free, exit
#include <ctype.h>  // For toupper

// --- Configuration ---
const char *SECRET_PASSPHRASE = "MySecretPass123!"; // Same as before

// --- Helper Function: Reverse the order of bytes in an array ---
void reverse_bytes(unsigned char *data, size_t len) {
    if (len == 0) return;
    unsigned char temp;
    for (size_t i = 0; i < len / 2; ++i) {
        temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}

// --- Helper Function: XOR data with passphrase (repeating passphrase if needed) ---
void xor_with_passphrase(unsigned char *data, size_t data_len, const char *passphrase) {
    size_t passphrase_len = strlen(passphrase);
    if (passphrase_len == 0) {
        fprintf(stderr, "Warning: Passphrase is empty. XORing will not occur.\n");
        return;
    }

    for (size_t i = 0; i < data_len; ++i) {
        data[i] = data[i] ^ passphrase[i % passphrase_len];
    }
}

// --- Encryption Function ---
void crypt_data(unsigned char *data, size_t data_len, const char *passphrase) {
    if (data == NULL || data_len == 0) {
        // For file encryption, an empty file is valid, it will just produce an empty array.
        // So, we might not want an error here, but a warning or just proceed.
        // Let's allow empty data for now, it will result in an empty encrypted array.
        if (data_len == 0) {
             printf("Note: Encrypting 0 bytes of data.\n");
        } else if (data == NULL) {
            fprintf(stderr, "Error: NULL data pointer passed to crypt_data.\n");
            return;
        }
    }
    if (passphrase == NULL || strlen(passphrase) == 0) {
        fprintf(stderr, "Error: Passphrase cannot be empty for encryption.\n");
        return; // Critical error for encryption
    }

    // 1. Reverse the order of bytes
    reverse_bytes(data, data_len);
    // 2. XOR with the secret passphrase
    xor_with_passphrase(data, data_len, passphrase);
}

// --- Decryption Function ---
void decrypt_data(unsigned char *data, size_t data_len, const char *passphrase) {
     if (data == NULL || data_len == 0) {
        if (data_len == 0) {
             printf("Note: Decrypting 0 bytes of data.\n");
        } else if (data == NULL) {
            fprintf(stderr, "Error: NULL data pointer passed to decrypt_data.\n");
            return;
        }
    }
     if (passphrase == NULL || strlen(passphrase) == 0) {
        fprintf(stderr, "Error: Passphrase cannot be empty for decryption.\n");
        return; // Critical error for decryption
    }

    // 1. XOR with the secret passphrase (XOR is its own inverse)
    xor_with_passphrase(data, data_len, passphrase);
    // 2. Reverse the order of bytes (reverses the original reversal)
    reverse_bytes(data, data_len);
}

// --- Helper to print byte array as hex (for non-printable characters) ---
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

// --- Helper to print byte array as string if possible, otherwise hex ---
void print_bytes_smart(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    if (len == 0) {
        printf("(empty)\n");
        return;
    }
    int all_printable = 1;
    for (size_t i = 0; i < len; ++i) {
        if (!((data[i] >= 32 && data[i] <= 126) || data[i] == '\0')) {
            all_printable = 0;
            break;
        }
    }

    if (all_printable && len > 0 && data[len-1] != '\0' && memchr(data, '\0', len-1) == NULL) {
        for(size_t i=0; i<len; ++i) printf("%c", data[i]);
        printf(" (as chars) / ");
        for (size_t i = 0; i < len; ++i) printf("%02X ", data[i]);
        printf("(as hex)");
    } else if (all_printable && len > 0 && memchr(data, '\0', len) != NULL) { // Contains null, print as string up to first null
        printf("\"%s\" (as string) / ", (const char*)data);
        for (size_t i = 0; i < len; ++i) printf("%02X ", data[i]);
        printf("(as hex)");
    } else {
        for (size_t i = 0; i < len; ++i) {
            printf("%02X ", data[i]);
        }
         printf("(as hex, contains non-printable or is empty)");
    }
    printf("\n");
}


// --- Function to encrypt a file and output a C header ---
// Returns 0 on success, -1 on failure
int encrypt_file_to_header(const char *input_filename,
                           const char *output_header_filename,
                           const char *array_name,
                           const char *passphrase) {
    FILE *infile = NULL;
    FILE *outfile = NULL;
    unsigned char *buffer = NULL;
    long file_size;

    // 1. Check arguments
    if (!input_filename || !output_header_filename || !array_name || !passphrase) {
        fprintf(stderr, "Error: Invalid arguments to encrypt_file_to_header.\n");
        return -1;
    }
    if (strlen(array_name) == 0) {
        fprintf(stderr, "Error: Array name cannot be empty.\n");
        return -1;
    }
    if (strlen(passphrase) == 0) {
        fprintf(stderr, "Error: Passphrase cannot be empty for file encryption.\n");
        return -1;
    }


    // 2. Open input file
    infile = fopen(input_filename, "rb"); // Read in binary mode
    if (!infile) {
        perror("Error opening input file");
        return -1;
    }

    // 3. Determine file size
    fseek(infile, 0, SEEK_END);
    file_size = ftell(infile);
    fseek(infile, 0, SEEK_SET); // or rewind(infile);

    if (file_size < 0) {
        perror("Error getting file size");
        fclose(infile);
        return -1;
    }
    
    printf("Input file '%s' size: %ld bytes\n", input_filename, file_size);

    // 4. Allocate memory (even for 0-byte files, malloc(0) is implementation-defined but often ok)
    // However, if file_size is 0, we can skip reading and directly write an empty array.
    if (file_size > 0) {
        buffer = (unsigned char *)malloc(file_size);
        if (!buffer) {
            fprintf(stderr, "Error: Memory allocation failed for %ld bytes.\n", file_size);
            fclose(infile);
            return -1;
        }

        // 5. Read file content
        size_t bytes_read = fread(buffer, 1, file_size, infile);
        if (bytes_read != (size_t)file_size) {
            fprintf(stderr, "Error reading input file: read %zu bytes, expected %ld\n", bytes_read, file_size);
            perror("fread error");
            fclose(infile);
            free(buffer);
            return -1;
        }
    }
    fclose(infile); // Close input file after reading

    // 6. Encrypt data (if any)
    if (file_size > 0 && buffer != NULL) { // Check buffer as well, though malloc(0) might give non-NULL
        printf("Encrypting file content...\n");
        crypt_data(buffer, file_size, passphrase);
    } else if (file_size == 0) {
        printf("Input file is empty. Encrypted output will be an empty array.\n");
    }


    // 7. Open output header file
    outfile = fopen(output_header_filename, "w");
    if (!outfile) {
        perror("Error opening output header file");
        if (buffer) free(buffer);
        return -1;
    }

    // 8. Write header preamble
    // Create a unique header guard from array_name
    char header_guard[256];
    snprintf(header_guard, sizeof(header_guard), "%s_H", array_name);
    for(int i = 0; header_guard[i]; i++){
      header_guard[i] = toupper((unsigned char)header_guard[i]);
      if (!isalnum((unsigned char)header_guard[i])) header_guard[i] = '_'; // Ensure valid C identifier
    }


    fprintf(outfile, "#ifndef %s\n", header_guard);
    fprintf(outfile, "#define %s\n\n", header_guard);
    fprintf(outfile, "#include <stddef.h> // For size_t\n\n");
    fprintf(outfile, "// Encrypted content of %s\n", input_filename);
    fprintf(outfile, "unsigned char %s[] = {\n", array_name);

    // 9. Write encrypted data as C array
    if (file_size > 0 && buffer != NULL) {
        for (long i = 0; i < file_size; ++i) {
            if (i % 12 == 0 && i != 0) { // Newline every 12 bytes for readability
                fprintf(outfile, "\n    ");
            } else if (i == 0) {
                fprintf(outfile, "    ");
            }
            fprintf(outfile, "0x%02X", buffer[i]);
            if (i < file_size - 1) {
                fprintf(outfile, ", ");
            }
        }
    }
    fprintf(outfile, "\n};\n\n");

    // 10. Write array size
    fprintf(outfile, "unsigned int %s_len = %ld;\n\n", array_name, file_size);

    // 11. Write header postamble
    fprintf(outfile, "#endif // %s\n", header_guard);

    // 12. Close output file
    fclose(outfile);
    printf("Successfully wrote encrypted data to %s (array name: %s)\n", output_header_filename, array_name);

    // 13. Free memory
    if (buffer) free(buffer);

    return 0;
}

#ifdef CRYPTOR_STANDALONE
int main(int argc, char *argv[]) {

    /*  1. Get a payload binary path from the command line
        2. Encrypt the payload
        3. Generate a header file
        4. Output help if arguments missing
        5. Validate argument (file name) is valid, exists, and is not empty */
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <input_file> <output_header> <array_name> [<passphrase>]\n", argv[0]);
        return 1;
    }
    const char *input_file = argv[1];
    const char *output_header = argv[2];
    const char *array_name = argv[3];
    const char *passphrase = (argc > 4) ? argv[4] : SECRET_PASSPHRASE;
    if (strlen(input_file) == 0 || strlen(output_header) == 0 || strlen(array_name) == 0) {
        fprintf(stderr, "Error: Input file, output header, and array name cannot be empty.\n");
        return 1;
    }
    int result = encrypt_file_to_header(input_file, output_header, array_name, passphrase);
    if (result != 0) {
        fprintf(stderr, "Error: Failed to encrypt file and generate header.\n");
        return result;
    }
    printf("Successfully encrypted '%s' to '%s' with array name '%s'.\n", input_file, output_header, array_name);
    printf("Use the generated header in your C/C++ code to access the encrypted data.\n");
    return 0;
}
#endif // CRYPTOR_STANDALONE
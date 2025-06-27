/*  A program to hash files using argon2 and encode in a base of user's choice
    Copyright (C) 2025 Anonymous1212144

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include "argon2.h"

const size_t char_pointer_size = sizeof(char*);

// Called when an error occured
void handle_error(const char *prompt)
{
    perror(prompt);
    getchar();
    exit(EXIT_FAILURE);
}

// Prompt for file name and then either read or write using output
const size_t get_file(const char *prompt, char **output, const char *default_file, size_t index)
{
    printf(prompt);

    char *file_name = malloc(1);
    size_t len = 0;
    size_t capacity = 1;

    for (int c = getchar(); c != EOF && c != '\n'; c = getchar())
    {
        if (len >= capacity)
        {
            capacity <<= 1;
            if (!capacity)
                capacity--;
            char *new_buffer = realloc(file_name, capacity);
            if (!new_buffer)
                handle_error("Error allocating buffer");
            file_name = new_buffer;
        }
        file_name[len++] = c;
    }
    file_name[len] = '\0';

    FILE *file;

    if (!len)
    {
        printf("Nothing entered, defaulting to \"%s\"\n", default_file);
        if (index)
            file = fopen(default_file, "wb");
        else
            file = fopen(default_file, "rb");
    }
    else
    {
        if (index)
            file = fopen(file_name, "wb");
        else
            file = fopen(file_name, "rb");
    }

    if (file == NULL)
        handle_error("Error opening file");
    free(file_name);

    if (index)
    {
        while (index--)
            fputs(output[index], file);
        return 0;
    }

    size_t outlen;
    fseek(file, 0, SEEK_END);
    outlen = ftell(file);
    rewind(file);

    // Allocate memory to store the file content
    *output = (char *)malloc(outlen);
    if (!*output)
        handle_error("Error loading file");

    // Read the file into the buffer
    fread(*output, 1, outlen, file);
    fclose(file);
    return outlen;
}

// Parse the character array to handle any unicode or string, delimined by \n, \r
const size_t parse(char ***char_array, const char *input, const size_t input_size)
{
    size_t char_array_size = 0;
    size_t current_char_size = 1;
    char *current_char = NULL;
    for (size_t i = 0; i <= input_size; i++)
    {
        if (input[i] == '\r' || input[i] == '\n' || i == input_size)
        {
            if (current_char_size - 1)
            {
                *char_array = realloc(*char_array, (++char_array_size) * char_pointer_size);
                if (!*char_array)
                    handle_error("Error parsing");
                current_char[current_char_size - 1] = '\0';
                (*char_array)[char_array_size - 1] = current_char;
                current_char = NULL;
                current_char_size = 1;
            }
        }
        else
        {
            current_char = realloc(current_char, ++current_char_size);
            if (!current_char)
                handle_error("Error parsing");
            current_char[current_char_size - 2] = input[i];
        }
    }
    return char_array_size;
}

// Prompt for a number
const uint32_t get_number(const char *message, const uint32_t default_number)
{
    char input[16];
    printf(message);
    if (!fgets(input, 16, stdin))
        handle_error("Error reading input");
    const uint32_t number = strtol(input, NULL, 0);
    if (!number)
    {
        printf("Invalid entry, choosing default value\n");
        return default_number;
    }
    return number;
}

// Calculate maximum required buffer for output encoding
const size_t buffer_size(const uintmax_t len, size_t base)
{
    size_t width = 0;
    while (base)
    {
        base >>= 1;
        width++;
    }
    return (len + 1) / (width - 1) + 1;
}

// Converts byte array into any base through long division
const size_t divide(uint8_t *dividend, uint32_t *size, const size_t divisor)
{
    uint8_t *pos = dividend;
    size_t total = 0;
    uint8_t first = 1;
    for (uint32_t i = *size; i; i--)
    {
        total = (total << 8) | *dividend;
        *pos = total / divisor;
        if (!*pos && first)
            (*size)--;
        else
        {
            pos++;
            first = 0;
        }
        dividend++;
        total %= divisor;
    }
    return total;
}

int main()
{
    // Prompt the users for info
    char *message;
    const uint32_t message_length = get_file("Enter message file name (file must be 0 to 4294967295 bytes): ", &message, "message.txt", 0);
    printf("Message length read as %u bytes\n", message_length);

    char *nonce;
    const uint32_t nonce_length = get_file("\nEnter nonce file name (file must be 8 to 4294967295 bytes): ", &nonce, "nonce.txt", 0);
    printf("Nonce length read as %u bytes\n", nonce_length);

    char *secret;
    const uint32_t secret_length = get_file("\nEnter secret value file name (file must be 0 to 4294967295 bytes): ", &secret, "secret.txt", 0);
    printf("Secret key length read as %u bytes\n", secret_length);

    char *associated_data;
    const uint32_t associated_data_length = get_file("\nEnter associated data file name (file must be 0 to 4294967295 bytes): ", &associated_data, "data.txt", 0);
    printf("Associated data length read as %d bytes\n", associated_data_length);

    char *chars_file;
    const size_t chars_file_length = get_file("\nEnter encoding character set file name (file must have at least 2 characters): ", &chars_file, "base94.txt", 0);
    char **chars;
    const size_t base = parse(&chars, chars_file, chars_file_length);
    printf("Found %zu characters\n", base);
    if (base < 2)
    {
        printf("Error: Not enough characters");
        getchar();
        return EXIT_FAILURE;
    }
    free(chars_file);

    uint32_t tag_length = get_number("\nEnter tag length (4 to 4294967295 bytes): ", 32);
    printf("Tag length read as %u bytes\n", tag_length);
    uint8_t *tag = malloc(tag_length);
    if (!tag)
        handle_error("Error initializing hash");

    const size_t output_size = buffer_size(((uintmax_t)tag_length) << 3, base) * char_pointer_size;
    char **output = malloc(output_size);
    if (!output)
        handle_error("Error initializing output");

    const uint32_t iterations = get_number("\nNumber of iterations (1 to 4294967295): ", 3);
    printf("Number of iterations read as %u\n", iterations);

    const uint32_t parallelism = get_number("\nDegree of parallelism (1 to 16777215): ", 1);
    printf("Degree of parallelism read as %u\n", parallelism);

    const uint32_t memory_size = get_number("\nMemory size (8*parallism to 4294967295 kibibytes): ", parallelism << 12);
    printf("Memory size read as %u kibibytes\n", memory_size);

    // Hash using the info given
    argon2_context context = {
        tag, tag_length,
        message, message_length,
        nonce, nonce_length,
        secret, secret_length,
        associated_data, associated_data_length,
        iterations, memory_size, parallelism, parallelism,
        ARGON2_VERSION_13,
        NULL, NULL,
        ARGON2_DEFAULT_FLAGS};

    printf("Hashing...");
    int code = argon2id_ctx(&context);
    if (code != ARGON2_OK)
    {
        printf("Error hashing: %s\n", argon2_error_message(code));
        getchar();
        return EXIT_FAILURE;
    }
    printf("Done\n");
    free(message);

    // Encode the hash and save to file
    size_t index = 0;
    while (tag_length)
        output[index++] = chars[divide(tag, &tag_length, base)];

    get_file("\nEnter output file name: ", output, "output.txt", index);
    printf("Done");

    return EXIT_SUCCESS;
}
/*  A program to hash files using argon2 and encode in a base of user's choice
    Copyright (C) 2026 Anonymous1212144

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "argon2.h"

const size_t char_pointer_size = sizeof(char *);
const size_t size_t_size = sizeof(size_t);

const size_t parse(const char **const char_start, const char **const char_end, size_t *const max_size, const char *const input, const size_t input_size)
{
    const char *const input_end = input + input_size;
    size_t char_num = 0;
    size_t state = 0;
    for (const char *i = input; i <= input_end; i++)
    {
        if (i == input_end || *i == '\r' || *i == '\n')
        {
            if (state)
            {
                char_end[char_num] = i;
                if (state > *max_size)
                    *max_size = state;
                state = 0;
                char_num++;
            }
        }
        else
        {
            if (!state)
                char_start[char_num] = i;
            state++;
        }
    }

    return char_num;
}

// Calculate maximum required buffer for output encoding
const size_t buffer_size(const uint64_t len, size_t base)
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
size_t divide(uint8_t *dividend, uint32_t *size, const size_t divisor)
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

const char *hash(char *const message, const uint32_t message_length,
                 char *const nonce, const uint32_t nonce_length,
                 char *const secret, const uint32_t secret_length,
                 char *const associated_data, const uint32_t associated_data_length,
                 char *const chars_file, const size_t chars_file_length,
                 uint32_t tag_length,
                 const uint32_t iterations,
                 const uint32_t parallelism,
                 const uint32_t memory_size)
{
    const char *result;

    size_t max_chars = chars_file_length + 1 >> 1;
    const char **const char_start = malloc(max_chars * char_pointer_size);
    const char **const char_end = malloc(max_chars * char_pointer_size);
    uint8_t *const tag = malloc(tag_length);
    if (!char_start || !char_end || !tag)
        goto cleanup;

    size_t max_size = 0;
    const size_t base = parse(char_start, char_end, &max_size, chars_file, chars_file_length);
    if (base < 2)
    {
        result = "Error: not enough characters";
        goto cleanup;
    }

    if (!tag)
    {
        result = "Error allocating memory";
        goto cleanup;
    }

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

    int code = argon2id_ctx(&context);
    if (code != ARGON2_OK)
    {
        result = argon2_error_message(code);
        goto cleanup;
    }

    const size_t output_size = buffer_size(((uint64_t)tag_length) << 3, base);
    char *const output = malloc(output_size * max_size + 100);
    size_t *const temp_out = malloc(output_size * size_t_size);
    if (!output || !temp_out)
    {
        result = "Error allocating memory";
        free(output);
        goto cleanup2;
    }

    // Encode the hash and save to file
    size_t index = 0;
    while (tag_length)
        temp_out[index++] = divide(tag, &tag_length, base);

    char *out_p = output + sprintf(output, "Found %zu characters\n", base);
    while (index--)
    {
        size_t c = temp_out[index];
        size_t size = char_end[c] - char_start[c];
        memcpy(out_p, char_start[c], size);
        out_p += size;
    }
    *out_p = 0;
    result = output;

cleanup2:
    free(temp_out);
cleanup:
    free(message);
    free(nonce);
    free(secret);
    free(associated_data);
    free(chars_file);
    free(char_start);
    free(char_end);
    free(tag);
    return result;
}
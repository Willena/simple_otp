/*
Simple_OTP C library
Copyright 2020 - Guillaume Villena <guillaume@villena.me>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "hmac.h"
#include "sha1.h"
#include "sha2.h"
#include "common.h"
#include "hotp.h"


/**
 * hotp_generate:
 * @secret: the shared secret string (a byte string)
 * @secret_length: length of @secret (number of bytes)
 * @moving_factor: a counter indicating the current OTP to generate
 * @digits: number of requested digits in the OTP, excluding checksum
 * @add_checksum: whether to add a checksum digit or not
 * @truncation_offset: use a specific truncation offset
 * @output_otp: output buffer, must have room for the output OTP plus zero ans eventually the checksum
 *
 * Generate a one-time-password using the HOTP algorithm as described
 * in RFC 4226.
 *
 * Use a value of %HOTP_DYNAMIC_TRUNCATION for @truncation_offset
 * unless you really need a specific truncation offset.
 *
 * To find out the size of the OTP you may use the HOTP_LENGTH()
 * macro.  The @output_otp buffer must be have room for that length
 * plus one for the terminating NUL.
 *
 * Currently only values 1 to 8 for @digits are supported
 *
 * @returns: On success, %OTP_OK (zero) is returned, otherwise an
 *   error code is returned.
 **/

int hotp_generate(const uint8_t *secret,
                  size_t secret_length,
                  uint64_t moving_factor,
                  unsigned digits,
                  bool add_checksum,
                  size_t truncation_offset,
                  otp_hmac_algorithm hmacAlgorithm,
                  uint8_t *output_otp) {

    uint8_t hs[CF_SHA512_HASHSZ];
    int hssize;
    long S;

    char counter[sizeof(moving_factor)];
    size_t i;
    cf_hmac_ctx ctx;

    for (i = 0; i < sizeof(counter); i++)
        counter[i] = (moving_factor >> ((sizeof(moving_factor) - i - 1) * 8)) & 0xFF;

    switch (hmacAlgorithm) {
        case OTP_HMAC_SHA1:
            hssize = CF_SHA1_HASHSZ;
            cf_hmac_init(&ctx, &cf_sha1, secret, secret_length);
            break;
        case OTP_HMAC_SHA512:
            hssize = CF_SHA512_HASHSZ;
            cf_hmac_init(&ctx, &cf_sha512, secret, secret_length);
            break;
        case OTP_HMAC_SHA256:
            hssize = CF_SHA256_HASHSZ;
            cf_hmac_init(&ctx, &cf_sha256, secret, secret_length);
            break;
        default:
            return OTP_INVALID_HMAC_ALGORITHM;
    }

    cf_hmac_update(&ctx, counter, sizeof moving_factor);
    cf_hmac_finish(&ctx, hs);

    uint8_t offset = hs[hssize - 1] & 0x0f;

    if ((0 <= truncation_offset) && (truncation_offset < (hssize - 4)))
        offset = truncation_offset;

    S = (((hs[offset] & 0x7f) << 24)
         | ((hs[offset + 1] & 0xff) << 16)
         | ((hs[offset + 2] & 0xff) << 8) | ((hs[offset + 3] & 0xff)));


    switch (digits) {
        case 1:
            S = S % 10;
            break;
        case 2:
            S = S % 100;
            break;
        case 3:
            S = S % 1000;
            break;
        case 4:
            S = S % 10000;
            break;
        case 5:
            S = S % 100000;
            break;
        case 6:
            S = S % 1000000;
            break;
        case 7:
            S = S % 10000000;
            break;
        case 8:
            S = S % 100000000;
            break;
        default:
            return OTP_INVALID_DIGIT_NUMBER;
    }

    if (add_checksum) {
        digits = HOTP_LENGTH(digits, add_checksum);
        S = (S * 10) + _checksumCalculation(S, digits);
    }

    {
        int len = snprintf(output_otp, digits + 1, "%.*ld", digits, S);
        output_otp[digits] = '\0';
        if (len <= 0 || ((unsigned) len) != digits)
            return OATH_PRINTF_ERROR;
    }

    return OTP_OK;
}

/**
 * _getDigitForChecksum:
 * @digit : the digit that need to be converted
 *
 * According to RFC 4226 reference implementation, this is needed.
 *
 * @return the converted digit
 */
int _getDigitForChecksum(int digit) {
    switch (digit) {
        case 0:
            return 0;
        case 1:
            return 2;
        case 2:
            return 4;
        case 3:
            return 6;
        case 4:
            return 8;
        case 5:
            return 1;
        case 6:
            return 3;
        case 7:
            return 5;
        case 8:
            return 7;
        case 9:
            return 9;
    }
}

/**
 * _checksumCalculation:
 * @otp : The otp the checksum needs to be calculated
 * @digits ; The number of digits in the OTP
 *
 * This function calculate the checksum for a given @otp that is @digits long.
 *
 * @returns: an extra digit that need to be appended to the OTP
 */
long _checksumCalculation(long otp, unsigned int digits) {
    bool doubleDigit = true;
    int total = 0;
    while (0 < digits--) {
        int digit = otp % 10;
        otp /= 10;
        if (doubleDigit)
            digit = _getDigitForChecksum(digit);

        total += digit;
        doubleDigit = !doubleDigit;
    }
    int result = total % 10;
    if (result > 0) {
        result = 10 - result;
    }
    return result;
}


/**
 * hotp_validate:
 * @secret: the shared secret string (byte string)
 * @secret_length: length of @secret (number of bytes)
 * @start_moving_factor: start counter in OTP stream
 * @window: how many OTPs after start counter to test (for example if the user generated few HOTP between verifications)
 * @otp: the OTP to validate.
 *
 * Validate an OTP according to OATH HOTP algorithm per RFC 4226.
 *
 * Currently only OTP lengths of 1 to 8 digits are supported.
 *
 * @returns: Returns position in OTP window (zero is first position),
 *   or %OTP_INVALID_OTP if no OTP was found in OTP window, or an
 *   error code.
 **/
int hotp_validate(const uint8_t *secret,
                  size_t secret_length,
                  uint64_t start_moving_factor,
                  size_t window,
                  otp_hmac_algorithm hmacAlgorithm,
                  const uint8_t *otp) {
    unsigned iter = 0;
    char tmp_otp[10];
    int rc;
    size_t digits = strlen(otp);

    do {
        rc = hotp_generate(secret,
                           secret_length,
                           start_moving_factor + iter,
                           digits,
                           false, HOTP_DYNAMIC_TRUNCATION, hmacAlgorithm, tmp_otp);
        if (rc != OTP_OK)
            return rc;
        if ((rc = strcmp(otp, tmp_otp)) == 0)
            return iter;
    } while (window - iter++ > 0);

    return OTP_INVALID_OTP;
}

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

#include <string.h>
#include "common.h"
#include "hotp.h"
#include "totp.h"

/**
 * totp_generate:
 * @secret: the shared secret string (byte string)
 * @secret_length: length of @secret (number of bytes)
 * @now: Unix time value to compute TOTP for
 * @time_step_size: time step system parameter (default 30)
 * @start_offset: Unix time of when to start counting time steps (default 0)
 * @digits: number of requested digits in the OTP
 * @hmacAlgorithm: hmacAlgorithm indicating mode, one of #otp_hmac_algorithm
 * @output_otp: output buffer, must have room for the output OTP plus zero
 *
 * Generate a one-time-password using the time-variant TOTP algorithm
 * described in RFC 6238.
 *
 * @time_step_size describes how long the time window for each OTP is.
 * The recommended value is 30 seconds.
 *
 * @start_offset denote the Unix time when time steps are started to be counted.
 * The recommended value is 0.
 *
 * The @output_otp buffer must have room for at least @digits
 * characters, plus one for the terminating NUL.
 *
 * Currently only values 1 to 8 for @digits are supported.
 *
 * @hmacAlgorithm can be used to change the HMAC function
 *
 * Returns: On success, %OTP_OK (zero) is returned, otherwise an
 *   error code is returned.
 *
 **/
int totp_generate(const uint8_t *secret,
                  size_t secret_length,
                  time_t now,
                  unsigned time_step_size,
                  time_t start_offset,
                  unsigned digits,
                  otp_hmac_algorithm hmacAlgorithm,
                  uint8_t *output_otp) {
    uint64_t nts;

    if (time_step_size == 0)
        time_step_size = TOTP_DEFAULT_TIME_STEP;

    nts = (now - start_offset) / time_step_size;

    return hotp_generate(secret,
                         secret_length,
                         nts,
                         digits,
                         false, HOTP_DYNAMIC_TRUNCATION, hmacAlgorithm,
                         output_otp);
}

/**
 * totp_validate:
 * @secret: the shared secret string (byte string)
 * @secret_length: length of @secret (number of bytes)
 * @now: Unix time value to validate TOTP for
 * @time_step_size: time step system parameter (typically 30)
 * @start_offset: Unix time of when to start counting time steps (default 0)
 * @window: how many OTPs after/before start OTP to test
 * @otp_pos: output search position in search window (may be NULL).
 * @otp_counter: counter value used to calculate OTP value (may be NULL).
 * @hmacAlgorithm: one of #otp_hmac_algorithm
 * @otp: the OTP to validate.
 *
 * Validate an OTP according to OATH TOTP algorithm per RFC 6238.
 *
 * Currently only OTP lengths of 1 to 8 digits are supported.
 *
 * The @hmacAlgorithm can be used to use another function.
 *
 * Returns: Returns absolute value of position in OTP window (zero is
 *   first position), or %OTP_INVALID_OTP if no OTP was found in OTP
 *   window, or an error code.
 **/
int totp_validate(const char *secret,
                  size_t secret_length,
                  time_t now,
                  unsigned time_step_size,
                  time_t start_offset,
                  size_t window,
                  int *otp_pos,
                  uint64_t *otp_counter,
                  otp_hmac_algorithm hmacAlgorithm,
                  const char *otp) {
    unsigned iter = 0;
    uint8_t tmp_otp[10];
    otp_status ret;
    size_t digits = strlen(otp);
    uint64_t nts;

    if (time_step_size == 0)
        time_step_size = TOTP_DEFAULT_TIME_STEP;

    nts = (now - start_offset) / time_step_size;

    do {
        ret = hotp_generate(secret,
                            secret_length,
                            nts + iter,
                            digits,
                            false,
                            HOTP_DYNAMIC_TRUNCATION,
                            hmacAlgorithm, tmp_otp);
        if (ret != OTP_OK)
            return ret;

        if (strcmp(otp, tmp_otp) == 0) {
            if (otp_counter)
                *otp_counter = nts + iter;
            if (otp_pos)
                *otp_pos = iter;
            return iter;
        }

        if (iter > 0) {
            ret = hotp_generate(secret,
                                secret_length,
                                nts - iter,
                                digits,
                                false,
                                HOTP_DYNAMIC_TRUNCATION,
                                hmacAlgorithm, tmp_otp);
            if (ret != OTP_OK)
                return ret;

            if ((ret = strcmp(otp, tmp_otp)) == 0) {
                if (otp_counter)
                    *otp_counter = nts - iter;
                if (otp_pos)
                    *otp_pos = -iter;
                return iter;
            }
        }
    } while (window - iter++ > 0);

    return OTP_INVALID_OTP;

}

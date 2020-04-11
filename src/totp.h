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

#ifndef SIMPLE_OTP_TOTP_H
#define SIMPLE_OTP_TOTP_H

#include <stdint.h>
#include <time.h>
#include "hotp.h"

#define TOTP_DEFAULT_TIME_STEP 30
#define TOTP_DEFAULT_START_TIME 0


int totp_generate(const uint8_t *secret,
                  size_t secret_length,
                  time_t now,
                  unsigned time_step_size,
                  time_t start_offset,
                  unsigned digits,
                  otp_hmac_algorithm hmacAlgorithm,
                  uint8_t *output_otp);


int totp_validate(const char *secret,
                  size_t secret_length,
                  time_t now,
                  unsigned time_step_size,
                  time_t start_offset,
                  size_t window,
                  int *otp_pos,
                  uint64_t *otp_counter,
                  otp_hmac_algorithm hmacAlgorithm,
                  const char *otp);


#endif //SIMPLE_OTP_TOTP_H

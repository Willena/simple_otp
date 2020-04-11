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

#ifndef SIMPLE_OTP_COMMON_H
#define SIMPLE_OTP_COMMON_H


/**
 * otp_status:
 * @OTP_OK: Successful executed
 * @OTP_INVALID_DIGIT_NUMBER: This number of digits is not supported
 * @OATH_PRINTF_ERROR: Error while printing the OTP in memory
 * @OTP_INVALID_OTP: The OTP given for verification is invalid
 * @OTP_INVALID_HMAC_ALGORITHM: The HMAC algorithm requested is not implemented
 *
 * Return codes for OTP functions.
 * All return codes are negative.
 *
 */

typedef enum {
    OTP_OK = 0,
    OTP_INVALID_DIGIT_NUMBER = -1,
    OATH_PRINTF_ERROR = -2,
    OTP_INVALID_OTP = -3,
    OTP_INVALID_HMAC_ALGORITHM = -4
} otp_status;


#endif //SIMPLE_OTP_COMMON_H

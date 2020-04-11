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
#include "hotp.h"
#include "totp.h"
#include <time.h>
#include "base32.h"

void main(){
    printf("OTP Library Example and quick testing");

    // Using same examples as RFC
    char secret[] = "12345678901234567890";

    uint8_t out[7] = {0};

    unsigned int OTP_iter = 10;

    for (unsigned int i =0; i < OTP_iter; i++)
    {
        hotp_generate(secret, sizeof secret, i, 6, false, HOTP_DYNAMIC_TRUNCATION, OTP_HMAC_SHA1, out);
        printf("\nHOTP %d : %s", i, out);
    }


    printf("\n\n");

    time_t currentTime = time(NULL);

    for (unsigned int i =0; i < OTP_iter; i++)
    {
        totp_generate(secret, sizeof(secret), currentTime + i * 30, 30, TOTP_DEFAULT_START_TIME, 6, OTP_HMAC_SHA1, out);
        printf("\nTOTP %d : %s", i, out);
    }


    printf("\n\nBase32 tests\n");
    char base32EncodedSecret[BASE32_LEN(sizeof(secret) - 1)] = {0};
    base32_encode(secret, sizeof(secret) - 1, base32EncodedSecret);

    printf("\nEncoded : %.*s", sizeof(base32EncodedSecret), base32EncodedSecret);


    char base32Secret[] = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    char base32decodedSecret[UNBASE32_LEN(sizeof(base32Secret))] = {0};
    base32_decode(base32Secret, base32decodedSecret);

    printf("\nDecoded : %s", base32decodedSecret);


    printf("\n\nTesting Validation function for HOTP");

    //This one should be ok
    char otp[] = "162583";
    otp_status res = hotp_validate(secret, sizeof(secret), 3, 10, OTP_HMAC_SHA1, otp);
    printf("\nRes %d : counter 3 window 10 otp : %s", res, otp);

    //This one should not be ok
    res = hotp_validate(secret, sizeof(secret), 3, 2, OTP_HMAC_SHA1, otp);
    printf("\nRes %d : counter 3 window 2 otp : %s", res, otp);


    printf("\n\nTesting Validation function for TOTP");
    // First should work
    totp_generate(secret, sizeof(secret), currentTime + 0 * 30, 30, TOTP_DEFAULT_START_TIME, 6, OTP_HMAC_SHA1, out);
    res = totp_validate(secret, sizeof(secret), time(NULL), 30, TOTP_DEFAULT_START_TIME, 2, NULL, NULL, OTP_HMAC_SHA1, out);
    printf("\nres : %d , totp : %s", res, out);

    // should not work
    totp_generate(secret, sizeof(secret), currentTime + 7 * 30, 30, TOTP_DEFAULT_START_TIME, 6, OTP_HMAC_SHA1, out);
    res = totp_validate(secret, sizeof(secret), time(NULL), 30, TOTP_DEFAULT_START_TIME, 2, NULL, NULL, OTP_HMAC_SHA1, out);
    printf("\nres : %d , totp : %s", res, out);



}
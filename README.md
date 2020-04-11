
# Simple_otp

A very simple HOTP and TOTP library.

# Documentation and usage

Simple_otp provides 4 main functions located in totp.c annd hotp.c

* 2 generators :
    * hotp_generate(...)
    * totp_generate(...)
* 2 validators:
    * hotp_validate(...)
    * totp_validate(...)

# How to

* Download the repository using git clone
```bash
git clone --recurse-submodules https://github.com/Willena/simple_otp.git
```
Do not forget to also clone the submodule. This library is using [cifra](https://github.com/ctz/cifrad) for the cryptographic backend.

* Run ` make`. It will build the library and the example/test application.

# Credits

This library is a simplified version inspired by the one included in [oath-toolkit](https://gitlab.com/oath-toolkit/oath-toolkit/).
This library is an adaptation of the reference implementation originally written in Java in RFC 4226,6238 
This library uses Adrien Kunysz implementation of Base32.

# License

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

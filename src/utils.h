/*
 * Copyright tos.network.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/include/openssl/ec.h>

void set_error_message(char *error_message, const char *message_prefix);
unsigned char *hex_to_bin(const char *hex_string);
char *hex_arr_to_str(const char *p, int p_len);
BIGNUM *get_curve_order(const int curve_nid, char *error_message);

#ifdef __cplusplus
extern
}
#endif
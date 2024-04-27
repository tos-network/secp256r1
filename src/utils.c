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
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "openssl/include/openssl/err.h"

#include "constants.h"
#include "utils.h"

void set_error_message(char *error_message, const char *message_prefix) {
  snprintf(error_message, 256, "%s: %s\n", message_prefix,
           ERR_error_string(ERR_get_error(), NULL));
}

unsigned char *hex_to_bin(const char *hex_string) {

  if (hex_string == NULL)
    return NULL;

  size_t slength = strlen(hex_string);
  if ((slength % 2) != 0) // must be even
    return NULL;

  size_t dlength = slength / 2;

  unsigned char *data = malloc(dlength);
  memset(data, 0, dlength);

  size_t index = 0;
  while (index < slength) {
    char c = hex_string[index];
    int value = 0;
    if (c >= '0' && c <= '9')
      value = (c - '0');
    else if (c >= 'A' && c <= 'F')
      value = (10 + (c - 'A'));
    else if (c >= 'a' && c <= 'f')
      value = (10 + (c - 'a'));
    else {
      free(data);
      return NULL;
    }

    data[(index / 2)] += value << (((index + 1) % 2) * 4);

    index++;
  }

  return data;
}

char *hex_arr_to_str(const char *p, int p_len) {
  int i;
  char tmp[3];
  int len = 2 * p_len + 1;
  char *output = malloc(len);
  memset(output, 0, len);
  for (i = 0; i < p_len; i++) {
    sprintf(tmp, "%02x", (unsigned char)p[i]);
    strcat(output, tmp);
  }

  return output;
}

BIGNUM *get_curve_order(const int curve_nid, char *error_message) {
  EC_GROUP *group = NULL;
  const BIGNUM *n_internal =
      NULL;         // interal pointer to curve order of the group
  BIGNUM *n = NULL; // curve order

  if ((group = EC_GROUP_new_by_curve_name(curve_nid)) == NULL) {
    set_error_message(error_message,
                      "Could not get EC_GROUP for requested curve: ");
    goto end_get_curve_order;
  }

  // returns the internal pointer of the curve order, which will be freed
  // automatically by calling EC_GROUP_free
  if ((n_internal = EC_GROUP_get0_order(group)) == NULL) {
    set_error_message(error_message,
                      "Could not convert curve order (n) to BIGNUM: ");
    goto end_get_curve_order;
  }

  // duplicate value of n in order to able to return it
  if ((n = BN_dup(n_internal)) == NULL) {
    set_error_message(error_message, "Could not copy curve order: ");
    goto end_get_curve_order;
  }

end_get_curve_order:
  EC_GROUP_free(group);

  return n;
}
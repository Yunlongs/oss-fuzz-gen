/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "ares.h"
#include "include/ares_buf.h"
#include "include/ares_mem.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

#ifdef USE_LEGACY_FUZZERS

/* This implementation calls the legacy c-ares parsers, which historically
 * all used different logic and parsing.  As of c-ares 1.21.0 these are
 * simply wrappers around a single parser, and simply convert the parsed
 * DNS response into the data structures the legacy parsers used which is a
 * small amount of code and not likely going to vary based on the input data.
 *
 * Instead, these days, it makes more sense to test the new parser directly
 * instead of calling it 10 or 11 times with the same input data to speed up
 * the number of iterations per second the fuzzer can perform.
 *
 * We are keeping this legacy fuzzer test for historic reasons or if someone
 * finds them of use.
 */

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  /* Feed the data into each of the ares_parse_*_reply functions. */
  struct hostent          *host = NULL;
  struct ares_addrttl      info[5];
  struct ares_addr6ttl     info6[5];
  unsigned char            addrv4[4] = { 0x10, 0x20, 0x30, 0x40 };
  struct ares_srv_reply   *srv       = NULL;
  struct ares_mx_reply    *mx        = NULL;
  struct ares_txt_reply   *txt       = NULL;
  struct ares_soa_reply   *soa       = NULL;
  struct ares_naptr_reply *naptr     = NULL;
  struct ares_caa_reply   *caa       = NULL;
  struct ares_uri_reply   *uri       = NULL;
  int                      count     = 5;
  ares_parse_a_reply(data, (int)size, &host, info, &count);
  if (host) {
    ares_free_hostent(host);
  }

  host  = NULL;
  count = 5;
  ares_parse_aaaa_reply(data, (int)size, &host, info6, &count);
  if (host) {
    ares_free_hostent(host);
  }

  host = NULL;
  ares_parse_ptr_reply(data, (int)size, addrv4, sizeof(addrv4), AF_INET, &host);
  if (host) {
    ares_free_hostent(host);
  }

  host = NULL;
  ares_parse_ns_reply(data, (int)size, &host);
  if (host) {
    ares_free_hostent(host);
  }

  ares_parse_srv_reply(data, (int)size, &srv);
  if (srv) {
    ares_free_data(srv);
  }

  ares_parse_mx_reply(data, (int)size, &mx);
  if (mx) {
    ares_free_data(mx);
  }

  ares_parse_txt_reply(data, (int)size, &txt);
  if (txt) {
    ares_free_data(txt);
  }

  ares_parse_soa_reply(data, (int)size, &soa);
  if (soa) {
    ares_free_data(soa);
  }

  ares_parse_naptr_reply(data, (int)size, &naptr);
  if (naptr) {
    ares_free_data(naptr);
  }

  ares_parse_caa_reply(data, (int)size, &caa);
  if (caa) {
    ares_free_data(caa);
  }

  ares_parse_uri_reply(data, (int)size, &uri);
  if (uri) {
    ares_free_data(uri);
  }

  return 0;
}

#else

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  ares_dns_record_t *dnsrec    = NULL;
  char              *printdata = NULL;
  ares_buf_t        *printmsg  = NULL;
  size_t             i;
  unsigned char     *datadup     = NULL;
  size_t             datadup_len = 0;

  /* There is never a reason to have a size > 65535, it is immediately
   * rejected by the parser */
  if (size > 65535) {
    return -1;
  }

  if (ares_dns_parse(data, size, 0, &dnsrec) != ARES_SUCCESS) {
    goto done;
  }

  /* Lets test the message fetchers */
  printmsg = ares_buf_create();
  if (printmsg == NULL) {
    goto done;
  }

  ares_buf_append_str(printmsg, ";; ->>HEADER<<- opcode: ");
  ares_buf_append_str(
    printmsg, ares_dns_opcode_tostr(ares_dns_record_get_opcode(dnsrec)));
  ares_buf_append_str(printmsg, ", status: ");
  ares_buf_append_str(printmsg,
                      ares_dns_rcode_tostr(ares_dns_record_get_rcode(dnsrec)));
  ares_buf_append_str(printmsg, ", id: ");
  ares_buf_append_num_dec(printmsg, (size_t)ares_dns_record_get_id(dnsrec), 0);
  ares_buf_append_str(printmsg, "\n;; flags: ");
  ares_buf_append_num_hex(printmsg, (size_t)ares_dns_record_get_flags(dnsrec),
                          0);
  ares_buf_append_str(printmsg, "; QUERY: ");
  ares_buf_append_num_dec(printmsg, ares_dns_record_query_cnt(dnsrec), 0);
  ares_buf_append_str(printmsg, ", ANSWER: ");
  ares_buf_append_num_dec(
    printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER), 0);
  ares_buf_append_str(printmsg, ", AUTHORITY: ");
  ares_buf_append_num_dec(
    printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY), 0);
  ares_buf_append_str(printmsg, ", ADDITIONAL: ");
  ares_buf_append_num_dec(
    printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL), 0);
  ares_buf_append_str(printmsg, "\n\n");
  ares_buf_append_str(printmsg, ";; QUESTION SECTION:\n");
  for (i = 0; i < ares_dns_record_query_cnt(dnsrec); i++) {
    const char         *name;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t    qclass;

    if (ares_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass) !=
        ARES_SUCCESS) {
      goto done;
    }

    ares_buf_append_str(printmsg, ";");
    ares_buf_append_str(printmsg, name);
    ares_buf_append_str(printmsg, ".\t\t\t");
    ares_buf_append_str(printmsg, ares_dns_class_tostr(qclass));
    ares_buf_append_str(printmsg, "\t");
    ares_buf_append_str(printmsg, ares_dns_rec_type_tostr(qtype));
    ares_buf_append_str(printmsg, "\n");

    /* Call ares_dns_record_query_set_name with the same name to exercise the function */
    if (ares_dns_record_query_set_name(dnsrec, i, name) != ARES_SUCCESS) {
      goto done;
    }
  }
  ares_buf_append_str(printmsg, "\n");
  for (i = ARES_SECTION_ANSWER; i < ARES_SECTION_ADDITIONAL + 1; i++) {
    size_t j;

    ares_buf_append_str(printmsg, ";; ");
    ares_buf_append_str(printmsg,
                        ares_dns_section_tostr((ares_dns_section_t)i));
    ares_buf_append_str(printmsg, " SECTION:\n");
    for (j = 0; j < ares_dns_record_rr_cnt(dnsrec, (ares_dns_section_t)i);
         j++) {
      size_t                   keys_cnt = 0;
      const ares_dns_rr_key_t *keys     = NULL;
      ares_dns_rr_t           *rr       = NULL;
      size_t                   k;

      rr = ares_dns_record_rr_get(dnsrec, (ares_dns_section_t)i, j);
      ares_buf_append_str(printmsg, ares_dns_rr_get_name(rr));
      ares_buf_append_str(printmsg, ".\t\t\t");
      ares_buf_append_str(printmsg,
                          ares_dns_class_tostr(ares_dns_rr_get_class(rr)));
      ares_buf_append_str(printmsg, "\t");
      ares_buf_append_str(printmsg,
                          ares_dns_rec_type_tostr(ares_dns_rr_get_type(rr)));
      ares_buf_append_str(printmsg, "\t");
      ares_buf_append_num_dec(printmsg, ares_dns_rr_get_ttl(rr), 0);
      ares_buf_append_str(printmsg, "\t");

      keys = ares_dns_rr_get_keys(ares_dns_rr_get_type(rr), &keys_cnt);
      for (k = 0; k < keys_cnt; k++) {
        char buf[256] = "";

        ares_buf_append_str(printmsg, ares_dns_rr_key_tostr(keys[k]));
        ares_buf_append_str(printmsg, "=");
        switch (ares_dns_rr_key_datatype(keys[k])) {
          case ARES_DATATYPE_INADDR:
            ares_inet_ntop(AF_INET, ares_dns_rr_get_addr(rr, keys[k]), buf,
                           sizeof(buf));
            ares_buf_append_str(printmsg, buf);
            break;
          case ARES_DATATYPE_INADDR6:
            ares_inet_ntop(AF_INET6, ares_dns_rr_get_addr6(rr, keys[k]), buf,
                           sizeof(buf));
            ares_buf_append_str(printmsg, buf);
            break;
          case ARES_DATATYPE_U8:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u8(rr, keys[k]),
                                    0);
            break;
          case ARES_DATATYPE_U16:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u16(rr, keys[k]),
                                    0);
            break;
          case ARES_DATATYPE_U32:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u32(rr, keys[k]),
                                    0);
            break;
          case ARES_DATATYPE_NAME:
          case ARES_DATATYPE_STR:
            ares_buf_append_byte(printmsg, '"');
            ares_buf_append_str(printmsg, ares_dns_rr_get_str(rr, keys[k]));
            ares_buf_append_byte(printmsg, '"');
            break;
          case ARES_DATATYPE_BIN:
            /* TODO */
            break;
          case ARES_DATATYPE_BINP:
            {
              size_t templen;
              ares_buf_append_byte(printmsg, '"');
              ares_buf_append_str(printmsg, (const char *)ares_dns_rr_get_bin(
                                              rr, keys[k], &templen));
              ares_buf_append_byte(printmsg, '"');
            }
            break;
          case ARES_DATATYPE_ABINP:
            {
              size_t a;
              for (a = 0; a < ares_dns_rr_get_abin_cnt(rr, keys[k]); a++) {
                size_t templen;

                if (a != 0) {
                  ares_buf_append_byte(printmsg, ' ');
                }
                ares_buf_append_byte(printmsg, '"');
                ares_buf_append_str(
                  printmsg,
                  (const char *)ares_dns_rr_get_abin(rr, keys[k], a, &templen));
                ares_buf_append_byte(printmsg, '"');
              }
            }
            break;
          case ARES_DATATYPE_OPT:
            /* TODO */
            break;
        }
        ares_buf_append_str(printmsg, " ");
      }
      ares_buf_append_str(printmsg, "\n");
    }
  }
  ares_buf_append_str(printmsg, ";; SIZE: ");
  ares_buf_append_num_dec(printmsg, size, 0);
  ares_buf_append_str(printmsg, "\n\n");

  printdata = ares_buf_finish_str(printmsg, NULL);
  printmsg  = NULL;

  /* Write it back out as a dns message to test writer */
  if (ares_dns_write(dnsrec, &datadup, &datadup_len) != ARES_SUCCESS) {
    goto done;
  }

done:
  /* Cleanup parser-based test resources */
  ares_dns_record_destroy(dnsrec);
  ares_buf_destroy(printmsg);
  ares_free(printdata);
  ares_free(datadup);

  /* --- Enhanced synthetic test to improve coverage --- */
  if (size > 0) {
    ares_dns_record_t *synth_rec = NULL;
    ares_status_t      status;
    size_t             offset = 0;
    unsigned char      n_queries;
    size_t             j;
    char             **stored_names = NULL;

    /* Test 1: DNS record with zero queries */
    status = ares_dns_record_create(&synth_rec, 0, 0, ARES_OPCODE_QUERY,
                                    ARES_RCODE_NOERROR);
    if (status == ARES_SUCCESS) {
      /* Should fail because there are no queries */
      ares_dns_record_query_set_name(synth_rec, 0, "test");
      ares_dns_record_destroy(synth_rec);
      synth_rec = NULL;
    }

    /* Test 2: DNS record with multiple queries */
    status = ares_dns_record_create(&synth_rec, 0, 0, ARES_OPCODE_QUERY,
                                    ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS) {
      return 0;
    }

    /* Determine number of queries to add (1-10) */
    n_queries = (size_t)(data[0] % 10) + 1;
    offset = 1;

    /* Allocate array to store the initial names */
    stored_names = malloc(n_queries * sizeof(char *));
    if (stored_names) {
      for (j = 0; j < n_queries; j++) {
        stored_names[j] = NULL;
      }
    }

    for (j = 0; j < n_queries; j++) {
      size_t name_len;
      char  *name;

      if (offset >= size) {
        break;
      }

      /* Use next byte as name length (1-255), but limit to remaining data */
      name_len = (size_t)(data[offset] % 255) + 1;
      offset++;
      if (name_len > size - offset) {
        name_len = size - offset;
      }
      if (name_len == 0) {
        /* If no data left, use empty string */
        name = strdup("");
      } else {
        name = malloc(name_len + 1);
        if (!name) {
          break;
        }
        memcpy(name, data + offset, name_len);
        name[name_len] = '\0';
        offset += name_len;
      }

      /* Store a copy of the name for later use */
      if (stored_names && j < n_queries) {
        stored_names[j] = strdup(name);
      }

      /* Add query with this name */
      ares_dns_record_query_add(synth_rec, name, ARES_REC_TYPE_A,
                                ARES_CLASS_IN);
      free(name);
    }

    size_t actual_queries = ares_dns_record_query_cnt(synth_rec);

    /* Test setting names for each query with various strings */
    for (j = 0; j < actual_queries; j++) {
      size_t name_len;
      char  *new_name;

      /* First set: use a slice of the input data */
      if (offset < size) {
        name_len = (size_t)(data[offset] % 100) + 1;
        offset++;
        if (name_len > size - offset) {
          name_len = size - offset;
        }
        if (name_len > 0) {
          new_name = malloc(name_len + 1);
          if (new_name) {
            memcpy(new_name, data + offset, name_len);
            new_name[name_len] = '\0';
            ares_dns_record_query_set_name(synth_rec, j, new_name);
            free(new_name);
            offset += name_len;
          }
        }
      }

      /* Second set: empty string */
      ares_dns_record_query_set_name(synth_rec, j, "");

      /* Third set: attempt with NULL (should fail) */
      ares_dns_record_query_set_name(synth_rec, j, NULL);

      /* Fourth set: very long string (using remaining data) */
      if (offset < size) {
        size_t remaining = size - offset;
        if (remaining > 0) {
          new_name = malloc(remaining + 1);
          if (new_name) {
            memcpy(new_name, data + offset, remaining);
            new_name[remaining] = '\0';
            ares_dns_record_query_set_name(synth_rec, j, new_name);
            free(new_name);
            offset = size; /* Consume all remaining data */
          }
        }
      }

      /* Fifth set: set back to the original name (if we stored it) */
      if (stored_names && j < n_queries && stored_names[j]) {
        ares_dns_record_query_set_name(synth_rec, j, stored_names[j]);
      }
    }

    /* Test error conditions */
    if (actual_queries > 0) {
      /* Valid index but NULL name */
      ares_dns_record_query_set_name(synth_rec, 0, NULL);
      /* Out-of-bounds index */
      ares_dns_record_query_set_name(synth_rec, actual_queries, "invalid");
      /* NULL dnsrec */
      ares_dns_record_query_set_name(NULL, 0, "test");
    }

    /* Cleanup stored names */
    if (stored_names) {
      for (j = 0; j < n_queries; j++) {
        if (stored_names[j]) {
          free(stored_names[j]);
        }
      }
      free(stored_names);
    }

    /* Cleanup DNS record */
    ares_dns_record_destroy(synth_rec);
  }

  return 0;
}

#endif
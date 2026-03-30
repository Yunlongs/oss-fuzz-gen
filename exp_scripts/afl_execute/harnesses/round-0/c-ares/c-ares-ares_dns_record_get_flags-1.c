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
#include <stdlib.h>
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
  ares_dns_record_t *dnsrec = NULL;
  unsigned short flags;

  /* Test with explicit NULL pointer */
  (void)ares_dns_record_get_flags(NULL);

  /* There is never a reason to have a size > 65535, it is immediately
   * rejected by the parser */
  if (size > 65535) {
    return -1;
  }

  /* Parse the input as a DNS record (existing code) */
  if (ares_dns_parse(data, size, 0, &dnsrec) == ARES_SUCCESS) {
    flags = ares_dns_record_get_flags(dnsrec);
    (void)flags;

    /* Write the parsed record to a buffer and parse it back */
    unsigned char *buf = NULL;
    size_t buf_len = 0;
    ares_status_t write_status = ares_dns_write(dnsrec, &buf, &buf_len);
    if (write_status == ARES_SUCCESS) {
      ares_dns_record_t *parsed_rec = NULL;
      if (ares_dns_parse(buf, buf_len, 0, &parsed_rec) == ARES_SUCCESS) {
        (void)ares_dns_record_get_flags(parsed_rec);
        ares_dns_record_destroy(parsed_rec);
      }
      ares_free(buf);
    }

    ares_dns_record_destroy(dnsrec);
  }

  /* Now test creating a DNS record with fuzzed parameters */
  if (size >= 6) {
    unsigned short id = (unsigned short)((data[0] << 8) | data[1]);
    unsigned short flags2 = (unsigned short)((data[2] << 8) | data[3]);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)data[4];
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)data[5];
    ares_dns_record_t *dnsrec2 = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec2, id, flags2,
                                                  opcode, rcode);
    if (status == ARES_SUCCESS) {
      (void)ares_dns_record_get_flags(dnsrec2);

      /* Write the created record and parse it back */
      unsigned char *buf2 = NULL;
      size_t buf_len2 = 0;
      ares_status_t write_status = ares_dns_write(dnsrec2, &buf2, &buf_len2);
      if (write_status == ARES_SUCCESS) {
        ares_dns_record_t *parsed_rec2 = NULL;
        if (ares_dns_parse(buf2, buf_len2, 0, &parsed_rec2) == ARES_SUCCESS) {
          (void)ares_dns_record_get_flags(parsed_rec2);
          ares_dns_record_destroy(parsed_rec2);
        }
        ares_free(buf2);
      }

      ares_dns_record_destroy(dnsrec2);
    }
  }

  /* Test creating a DNS query with fuzzed name and parameters */
  if (size >= 8) {
    unsigned short id = (unsigned short)((data[0] << 8) | data[1]);
    unsigned short flags3 = (unsigned short)((data[2] << 8) | data[3]);
    /* We ignore max_udp_size for simplicity, as EDNS is not required for basic query creation */
    char *name = NULL;
    if (size > 8) {
      name = malloc(size - 8 + 1);
      if (name) {
        memcpy(name, data + 8, size - 8);
        name[size - 8] = '\0';
      }
    } else {
      /* Empty string */
      name = malloc(1);
      if (name) {
        name[0] = '\0';
      }
    }
    if (name) {
      ares_dns_record_t *dnsrec3 = NULL;
      ares_status_t status = ares_dns_record_create(&dnsrec3, id, flags3,
                                                    ARES_OPCODE_QUERY,
                                                    ARES_RCODE_NOERROR);
      if (status == ARES_SUCCESS) {
        status = ares_dns_record_query_add(dnsrec3, name,
                                           ARES_REC_TYPE_A, ARES_CLASS_IN);
        if (status == ARES_SUCCESS) {
          (void)ares_dns_record_get_flags(dnsrec3);

          /* Write the query record and parse it back */
          unsigned char *buf3 = NULL;
          size_t buf_len3 = 0;
          ares_status_t write_status = ares_dns_write(dnsrec3, &buf3, &buf_len3);
          if (write_status == ARES_SUCCESS) {
            ares_dns_record_t *parsed_rec3 = NULL;
            if (ares_dns_parse(buf3, buf_len3, 0, &parsed_rec3) == ARES_SUCCESS) {
              (void)ares_dns_record_get_flags(parsed_rec3);
              ares_dns_record_destroy(parsed_rec3);
            }
            ares_free(buf3);
          }
        }
        ares_dns_record_destroy(dnsrec3);
      }
      free(name);
    }
  }

  /* Additionally, test each valid flag bit individually */
  if (size >= 2) {
    unsigned short base_id = 0x1234;
    ares_dns_opcode_t base_opcode = ARES_OPCODE_QUERY;
    ares_dns_rcode_t base_rcode = ARES_RCODE_NOERROR;
    unsigned short flag_bits[] = {
      ARES_FLAG_QR, ARES_FLAG_AA, ARES_FLAG_TC, ARES_FLAG_RD,
      ARES_FLAG_RA, ARES_FLAG_AD, ARES_FLAG_CD
    };
    int i;
    for (i = 0; i < sizeof(flag_bits)/sizeof(flag_bits[0]); i++) {
      ares_dns_record_t *test_rec = NULL;
      ares_status_t status = ares_dns_record_create(&test_rec, base_id, flag_bits[i],
                                                    base_opcode, base_rcode);
      if (status == ARES_SUCCESS) {
        (void)ares_dns_record_get_flags(test_rec);
        ares_dns_record_destroy(test_rec);
      }
    }
  }

  /* Enhanced test: create a DNS record with a variety of query types,
   * multiple queries, an answer, and an OPT record.
   */
  if (size >= 12) {
    /* Use the first byte to pick a query type from a list */
    ares_dns_rec_type_t query_types[] = {
      ARES_REC_TYPE_A,
      ARES_REC_TYPE_NS,
      ARES_REC_TYPE_CNAME,
      ARES_REC_TYPE_SOA,
      ARES_REC_TYPE_PTR,
      ARES_REC_TYPE_MX,
      ARES_REC_TYPE_TXT,
      ARES_REC_TYPE_AAAA,
      ARES_REC_TYPE_SRV,
      ARES_REC_TYPE_NAPTR,
      ARES_REC_TYPE_URI,
      ARES_REC_TYPE_CAA,
    };
    unsigned int type_idx = data[0] % (sizeof(query_types)/sizeof(query_types[0]));
    ares_dns_rec_type_t qtype = query_types[type_idx];

    /* Use the second byte for number of queries (1‑10) */
    unsigned int num_queries = (data[1] % 10) + 1;

    /* Use the next two bytes for id and flags */
    unsigned short id = (unsigned short)((data[2] << 8) | data[3]);
    unsigned short flags4 = (unsigned short)((data[4] << 8) | data[5]);

    /* Determine where the name(s) start */
    size_t name_start = 6;
    size_t remaining = size - name_start;
    if (remaining > 0) {
      ares_dns_record_t *dnsrec4 = NULL;
      ares_status_t status = ares_dns_record_create(&dnsrec4, id, flags4,
                                                    ARES_OPCODE_QUERY,
                                                    ARES_RCODE_NOERROR);
      if (status == ARES_SUCCESS) {
        /* Add multiple queries */
        unsigned int q;
        const unsigned char *name_ptr = data + name_start;
        size_t name_len = 0;
        for (q = 0; q < num_queries && remaining > 0; q++) {
          /* Find the length of the next name (up to next zero byte or end) */
          name_len = 0;
          while (name_len < remaining && name_ptr[name_len] != 0) {
            name_len++;
          }
          if (name_len == 0) {
            /* Empty name, skip */
            name_ptr++;
            remaining--;
            continue;
          }
          char *qname = malloc(name_len + 1);
          if (qname) {
            memcpy(qname, name_ptr, name_len);
            qname[name_len] = '\0';
            status = ares_dns_record_query_add(dnsrec4, qname, qtype,
                                               ARES_CLASS_IN);
            free(qname);
            if (status != ARES_SUCCESS) {
              break;
            }
          }
          name_ptr += name_len;
          remaining -= name_len;
          if (remaining > 0 && *name_ptr == 0) {
            /* Skip the zero terminator */
            name_ptr++;
            remaining--;
          }
        }

        /* If we have at least 4 more bytes and the query type is A,
         * add an A record answer.
         */
        if (qtype == ARES_REC_TYPE_A && remaining >= 4) {
          ares_dns_rr_t *rr_answer = NULL;
          status = ares_dns_record_rr_add(&rr_answer, dnsrec4,
                                          ARES_SECTION_ANSWER,
                                          "example.com",
                                          ARES_REC_TYPE_A,
                                          ARES_CLASS_IN, 300);
          if (status == ARES_SUCCESS) {
            unsigned char addr[4];
            memcpy(addr, name_ptr, 4);
            status = ares_dns_rr_set_addr(rr_answer, ARES_RR_A_ADDR, addr);
            /* Ignore result for fuzzing */
          }
          name_ptr += 4;
          remaining -= 4;
        }

        /* Add an OPT record (EDNS) if we have at least 2 more bytes */
        if (remaining >= 2) {
          ares_dns_rr_t *rr_opt = NULL;
          status = ares_dns_record_rr_add(&rr_opt, dnsrec4,
                                          ARES_SECTION_ADDITIONAL,
                                          "",
                                          ARES_REC_TYPE_OPT,
                                          ARES_CLASS_IN, 0);
          if (status == ARES_SUCCESS) {
            unsigned short udp_payload = (unsigned short)((name_ptr[0] << 8) | name_ptr[1]);
            status = ares_dns_rr_set_u16(rr_opt, ARES_RR_OPT_UDP_SIZE,
                                         udp_payload);
            /* Ignore result for fuzzing */
          }
        }

        /* Call the target function */
        (void)ares_dns_record_get_flags(dnsrec4);

        /* Write the record and parse it back */
        unsigned char *buf4 = NULL;
        size_t buf_len4 = 0;
        ares_status_t write_status = ares_dns_write(dnsrec4, &buf4, &buf_len4);
        if (write_status == ARES_SUCCESS) {
          ares_dns_record_t *parsed_rec4 = NULL;
          if (ares_dns_parse(buf4, buf_len4, 0, &parsed_rec4) == ARES_SUCCESS) {
            (void)ares_dns_record_get_flags(parsed_rec4);
            ares_dns_record_destroy(parsed_rec4);
          }
          ares_free(buf4);
        }

        ares_dns_record_destroy(dnsrec4);
      }
    }
  }

  return 0;
}

#endif
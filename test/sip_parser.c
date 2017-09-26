#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>

#include "sip_parser.h"


/*************************** Mini SIP parser (internals) ***************/

/*
 * SIP ABNF can be found here:
 *   http://tools.ietf.org/html/rfc3261#section-25
 * In 2014, there is a very helpful site that lets you browse the ABNF
 * easily:
 *   http://www.tech-invite.com/fo-abnf/tinv-fo-abnf-sip.html
 */


#if INTERFACE
#define MAX_HEADER_LEN 2049
#endif
/*************************** Mini SIP parser (externals) ***************/

/* strlen: return length of string s */
//LOCAL int sipstrlen(char *s)
//{
//    int n;
//    for (n = 0; *s != ' '; s++)
//        n++;
//    return n;
//}



LOCAL unsigned char *internal_find_header(unsigned char *msg, const char *name, bool content )
{
    unsigned char *ptr = msg;
    int namelen = strlen(name);

    while (1) {
        /* RFC3261, 7.3.1: When comparing header fields, field names
         *   To:...;tag=bla == TO:...;TAG=BLA
         * But:
         *   Warning: "something" != Warning: "SoMeThInG"
         */
        if (strncasecmp(ptr, name, namelen) == 0 ) {
            const char *tmp = ptr + namelen ;
            while (*tmp == ' ') {
                ++tmp;
            }
            if (*tmp == ':') {
                /* Found */
                if (content){
                    /* We just want the content */
                    ptr = internal_skip_lws(tmp + 1);
                }
                break;
            }
        }

        /* Seek to next line, but not past EOH */
        ptr = strchr(ptr, '\n');
        if (!ptr || ptr[-1] != '\r' || (ptr[1] == '\r' && ptr[2] == '\n')) {
            return NULL;
        }
        ++ptr;
    }
    return ptr;
}

LOCAL const char *internal_skip_lws(const char *ptr)
{
    while (1) {
        while (*ptr == ' ') {
            ++ptr;
        }
        return ptr;
    }
    return NULL; /* never gets here */

}


LOCAL unsigned char *internal_hdrchr(unsigned char *ptr, const char needle)
{
    if (*ptr == '\n') {
        return NULL; /* stray LF */

    }

    while (1) {
        if (*ptr == '\0') {
            return NULL;

        } else if (*ptr == needle) {
            return ptr;

        } else if (*ptr == '\n') {
            if (ptr[-1] == '\r' && ptr[1] != '\r' && ptr[1] != '\n') {
                return NULL; /* end of header */
            }
        }
        ++ptr;
    }
    return NULL; /* never gets here */
}

LOCAL unsigned char *internal_find_param(unsigned char *ptr, const char *name)
{
    int namelen = strlen(name);

    while (1) {
        ptr = internal_hdrchr(ptr, ';');
        if (!ptr) {
            return NULL;

        }
        ++ptr;

        ptr = internal_skip_lws(ptr);
        if (!ptr || !*ptr) {
            return NULL;

        }

        /* Case insensitive, see RFC 3261 7.3.1 notes above. */
        if (strncasecmp(ptr, name, namelen) == 0 && *(ptr + namelen) == '=') {
            ptr += namelen + 1;
            return ptr;

        }

    }

    return NULL; /* never gets here */

}



LOCAL const char *internal_hdrend(const char *ptr)
{
    const char *p = ptr;
    while(*p){
        if(p[0] == '\r' && p[1] == '\n'){
            return p;
        }
        ++p;
    }
    return p;
}

unsigned long int get_cseq_value(char *msg)
{
    char *ptr1;

    ptr1 = strstr(msg, "\r\nCSeq:");
    if (!ptr1) {
        printf("No valid Cseq header in request %s", msg);
        return 0;
    }

    ptr1 += 7;

    while (*ptr1 == ' ') {
        ++ptr1;
    }
    if (!*ptr1) {
        printf("No valid Cseq data in header");
        return 0;
    }

    return strtoul(ptr1, NULL, 10);
}

char * get_first_line(const char * message)
{
    /* non reentrant. consider accepting char buffer as param */
    static char last_header[MAX_HEADER_LEN * 10];
    const char * src;

    /* returns empty string in case of error */
    memset(last_header, 0, sizeof(last_header));

    if (!message || !*message) {
        return last_header;
    }

    src = message;

    int i=0;
    while (*src) {
        if (*src == '\n' || *src == '\r') {
            break;
        }
        last_header[i] = *src;
        i++;
        src++;
    }

    return last_header;
}

unsigned long get_reply_code(char *msg)
{
    while (msg && *msg != ' ')
        ++msg;
    while (msg && (*msg == ' '))
        ++msg;

    if (msg && strlen(msg) > 0) {
        return atol(msg);

    }
    return 0;

}

char *get_from_tag(unsigned char *msg)
{
    static char tag[MAX_HEADER_LEN];
    unsigned char * to_hdr;
    unsigned char *ptr;
    int     tag_i = 0;

    /* Find start of header */
    to_hdr = internal_find_header(msg, "From", true);
    if (!to_hdr) {
        printf("No valid To: header in reply\n");
        return NULL;
    }

    /* Skip past display-name */
    /* FIXME */

    /* Skip past LA/RA-quoted addr-spec if any */
    ptr = internal_hdrchr(to_hdr, '>');
    if (!ptr) {
        /* Maybe an addr-spec without quotes */
        ptr = to_hdr;
    }

    /* Find tag in this header */
    ptr = internal_find_param(ptr, "tag");
    if (!ptr) {
        return NULL;
    }

    while (*ptr && *ptr != ' ' && *ptr != ';' && *ptr != '\t' &&
            *ptr != '\r' && *ptr != '\n') {
        tag[tag_i++] = *(ptr++);
    }
    tag[tag_i] = '\0';

    return tag;
}

char *get_to_tag(unsigned char *msg)
{
    static char tag[MAX_HEADER_LEN];
    unsigned char * to_hdr;
    unsigned char *ptr;
    int     tag_i = 0;

    /* Find start of header */
    to_hdr = internal_find_header(msg, "To", true);
    if (!to_hdr) {
        printf("No valid To: header in reply\n");
        return NULL;
    }

    /* Skip past display-name */
    /* FIXME */

    /* Skip past LA/RA-quoted addr-spec if any */
    ptr = internal_hdrchr(to_hdr, '>');
    if (!ptr) {
        /* Maybe an addr-spec without quotes */
        ptr = to_hdr;
    }

    /* Find tag in this header */
    ptr = internal_find_param(ptr, "tag");
    if (!ptr) {
        return NULL;
    }

    while (*ptr && *ptr != ' ' && *ptr != ';' && *ptr != '\t' &&
            *ptr != '\r' && *ptr != '\n') {
        tag[tag_i++] = *(ptr++);
    }
    tag[tag_i] = '\0';

    return tag;
}


char * get_call_id(unsigned char *msg)
{
    static char call_id[MAX_HEADER_LEN];
    const char *content, *end_of_header;
    unsigned length;

    call_id[0] = '\0';

    content = internal_find_header(msg, "Call-ID", true);
    if(!content){
        printf("(1) No valid Call-ID: header in reply '%s'", msg);
        return call_id;
    }

    /* Always returns something */
    end_of_header = internal_hdrend(content);
    length = end_of_header - content;
    if (length + 1 > MAX_HEADER_LEN) {
        printf("(1) Call-ID: header too long in reply '%s'", msg);
        return call_id;

    }

    memcpy(call_id, content, length);
    call_id[length] = '\0';
    return call_id;
}

/* For this message
 * REGISTER sip:ccm-shnvtg-012 SIP/2.0
 * Via: SIP/2.0/TCP 10.140.80.180:59857;branch=z9hG4bK00004b17
 * From: <sip:88897032@ccm-shnvtg-012>;tag=54ee759851f0040400003d4c-0000370b
 * To: <sip:88897032@ccm-shnvtg-012> 
 *
 * name is "From:", 
 * return is "<sip:88897032@ccm-shnvtg-012>;tag=54ee759851f0040400003d4c-0000370b"
 */

char * get_header(const char* message, const char * name, bool content)
{
    /* non reentrant. consider accepting char buffer as param */
    static char last_header[MAX_HEADER_LEN * 10];
    char *src, *src_orig, *dest, *start, *ptr;
    /* Are we searching for a short form header? */
    bool short_form = false;
    bool first_time = true;
    char header_with_newline[MAX_HEADER_LEN + 1];

    /* returns empty string in case of error */
    last_header[0] = '\0';

    if (!message || !*message) {
        return last_header;

    }

    /* for safety's sake */
    if (!name || !strrchr(name, ':')) {
        printf("Can not search for header (no colon): %s", name ? name : "(null)");
        return last_header;

    }

    src_orig = strdup(message);

    do {
        /* We want to start from the beginning of the message each time
         *          * through this loop, because we may be searching for a short form. */
        src = src_orig;

        snprintf(header_with_newline, MAX_HEADER_LEN, "\n%s", name);
        dest = last_header;

        while ((src = strcasestr(src, header_with_newline))) {
            if (content || !first_time) {
                /* Just want the header's content, so skip over the header
                 *                  * and newline */
                src += strlen(name) + 1;
                /* Skip over leading spaces. */
                while (*src == ' ') {
                    src++;

                }

            } else {
                /* Just skip the newline */
                src++;

            }
            first_time = false;
            ptr = strchr(src, '\n');

            /* Multiline headers always begin with a tab or a space
             *              * on the subsequent lines. Skip those lines. */
            while (ptr && (*(ptr+1) == ' ' || *(ptr+1) == '\t')) {
                ptr = strchr(ptr + 1, '\n');

            }

            if (ptr) {
                *ptr = 0;

            }
            // Add ", " when several headers are present
            if (dest != last_header) {
                /* Remove trailing whitespaces, tabs, and CRs */
                while (dest > last_header &&
                        (*(dest-1) == ' ' ||
                         *(dest-1) == '\r' ||
                         *(dest-1) == '\n' ||
                         *(dest-1) == '\t')) {
                    *(--dest) = 0;
                }

                dest += sprintf(dest, ", ");
            }
            dest += sprintf(dest, "%s", src);
            if (ptr) {
                *ptr = '\n';
            }

            src++;
        }
        /* We found the header. */
        if (dest != last_header) {
            break;
        }
        /* We didn't find the header, even in its short form. */
        if (short_form) {
            free(src_orig);
            return last_header;
        }

        /* We should retry with the short form. */
        short_form = true;
        if (!strcasecmp(name, "call-id:")) {
            name = "i:";
        } else if (!strcasecmp(name, "contact:")) {
            name = "m:";
        } else if (!strcasecmp(name, "content-encoding:")) {
            name = "e:";
        } else if (!strcasecmp(name, "content-length:")) {
            name = "l:";
        } else if (!strcasecmp(name, "content-type:")) {
            name = "c:";
        } else if (!strcasecmp(name, "from:")) {
            name = "f:";
        } else if (!strcasecmp(name, "to:")) {
            name = "t:";
        } else if (!strcasecmp(name, "via:")) {
            name = "v:";
        } else {
            /* There is no short form to try. */
            free(src_orig);
            return last_header;
        }
    } while (1);

    *(dest--) = 0;

    /* Remove trailing whitespaces, tabs, and CRs */
    while (dest > last_header &&
            (*dest == ' ' || *dest == '\r' || *dest == '\t')) {
        *(dest--) = 0;
    }

    /* Remove leading whitespaces */
    for (start = last_header; *start == ' '; start++);

    /* remove enclosed CRs in multilines */
    /* don't remove enclosed CRs for multiple headers (e.g. Via) (Rhys) */
    while ((ptr = strstr(last_header, "\r\n")) != NULL &&
            (*(ptr + 2) == ' ' || *(ptr + 2) == '\r' || *(ptr + 2) == '\t')) {
        /* Use strlen(ptr) to include trailing zero */
        memmove(ptr, ptr+1, strlen(ptr));
    }

    /* Remove illegal double CR characters */
    while ((ptr = strstr(last_header, "\r\r")) != NULL) {
        memmove(ptr, ptr+1, strlen(ptr));
    }
    /* Remove illegal double Newline characters */
    while ((ptr = strstr(last_header, "\n\n")) != NULL) {
        memmove(ptr, ptr+1, strlen(ptr));
    }

    free(src_orig);
    return start;
}

char * get_header_content(const char* message, const char * name)
{
    return get_header(message, name, true);
}

void extract_cseq_method(char* method, char* msg)
{
    char* cseq ;
    if ((cseq = strstr (msg, "CSeq"))) {
        char * value ;
        if (( value = strchr (cseq,  ':') )) {
            value++;
            while ( isspace(*value) ) value++;  // ignore any white spaces after the :
            while ( !isspace(*value) ) value++;  // ignore the CSEQ number
            while ( isspace(*value) ) value++;  // ignore spaces after CSEQ number
            char *end = value;
            int nbytes = 0;
            /* A '\r' terminates the line, so we want to catch that too. */
            while ((*end != '\r') && (*end != '\n')) {
                end++;
                nbytes++;
            }
            if (nbytes > 0) strncpy (method, value, nbytes);
            method[nbytes] = '\0';
        }
    }
}

void extract_transaction(char* txn, char* msg)
{
    char *via = get_header_content(msg, "via:");
    if (!via) {
        txn[0] = '\0';
        return;
    }

    char *branch = strstr(via, ";branch=");
    if (!branch) {
        txn[0] = '\0';
        return;
    }

    branch += strlen(";branch=");
    while (*branch && *branch != ';' && *branch != ',' && !isspace(*branch)) {
        *txn++ = *branch++;

    }
    *txn = '\0';
}


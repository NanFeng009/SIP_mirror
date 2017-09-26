/* This file was automatically generated.  Do not edit! */
void extract_transaction(char *txn,char *msg);
void extract_cseq_method(char *method,char *msg);
char *get_header_content(const char *message,const char *name);
char *get_header(const char *message,const char *name,bool content);
char *get_call_id(unsigned char *msg);
char *get_to_tag(unsigned char *msg);
char *get_from_tag(unsigned char *msg);
unsigned long get_reply_code(char *msg);
char *get_first_line(const char *message);
unsigned long int get_cseq_value(char *msg);
#define LOCAL static
LOCAL const char *internal_hdrend(const char *ptr);
LOCAL unsigned char *internal_find_param(unsigned char *ptr,const char *name);
LOCAL unsigned char *internal_hdrchr(unsigned char *ptr,const char needle);
LOCAL const char *internal_skip_lws(const char *ptr);
LOCAL unsigned char *internal_find_header(unsigned char *msg,const char *name,bool content);
#define MAX_HEADER_LEN 2049
#define INTERFACE 0

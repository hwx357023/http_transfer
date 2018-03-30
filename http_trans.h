#ifndef __HTTP_TRANS_H__
#define __HTTP_TRANS_H__

#define HTTP_ERR 1
#define HTTP_OK 0

#define HTTP_TRUE  1
#define HTTP_FALSE 0

typedef unsigned char HTTP_BOOL;

//when a section is over and the next haven't began yet in chunked mode, this moment is called JOIN.
//when joinning, the join content need to be cached.
/* the max cache len is the size of (\r\nFFFFFFFF\r\n), that is 12, as the max hex of section lenght is 8 Fs*/
#define HTTP_JOIN_CACHE_MAX_LEN  12
#define DOUBLELRLF               "\r\n\r\n"


#define error(M, ...) fprintf(stderr, "ERROR %s (in function '%s'):%d:  " M "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define RET_NOTOK(ret,M,...) if(ret != HTTP_OK) { error(M,##__VA_ARGS__); return ret;}
#define JUMP_NOTOK(ret,label,M,...) if(ret != HTTP_OK) { error(M,##__VA_ARGS__); goto label;}

// the status is the stage of receiving http. That includes head, content and finish.
typedef enum http_trans_status_en
{
    TRANS_STATUS_HEADER,
    TRANS_STATUS_CONTENT,
    TRANS_STATUS_FINISH
} HTTP_TRANS_STATUS;

/* the mode of transfering content that includes content_len and chunked */
typedef enum http_trans_type_en
{
    TRANS_TYPE_CONTENT_LEN,
    TRANS_TYPE_CHUNKED
} HTTP_TRANS_TYPE;

typedef enum http_chunked_status_en
{
	/* content means when receiving content.That is to say I already know the section total len that is in the beginning of every section. */
    CHUNKED_STATUS_CONTENT,
	/* a section is over and the next don't begin. That is to say I don't know the total len of the next section. */
    CHUNKED_STATUS_JOIN,

} HTTP_CHUNKED_STATUS;


typedef struct http_trans_st
{
    char* header;
    char* content;

    size_t header_len;
    /* received already */
    size_t content_len;
    /* the field is valid only in content_len mode */
    size_t content_total;

    /* received already on the current section */
    size_t chunked_len;
    /* current section's total length*/
    size_t chunked_total;

    /* cache to handle join */
    char  join_cache[HTTP_JOIN_CACHE_MAX_LEN + 1];
    size_t cache_len;

    HTTP_CHUNKED_STATUS chunked_status;

    HTTP_TRANS_STATUS status;

    HTTP_TRANS_TYPE trans_type;
} HTTP_TRANS;

void http_trans_free(HTTP_TRANS* p);
int http_push_packet(HTTP_TRANS* http, char* buf, size_t len);

#endif/*__CHM_COMMU_H__*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http_trans.h"



int http_trans_chunked(HTTP_TRANS* http, char* buf_in, size_t len_in);

int http_push_packet(HTTP_TRANS* http, char* buf, size_t len);

/* return if suceed */
HTTP_BOOL TOOL_atosize(const char *s, size_t *d)
{
    int i = 0;
    size_t n = 0;
    const char *p = s;

    while(*p != 0)
    {
        if(*p <= '9' && *p >= '0')
        {
            i++;
        }
        else
        {
            break;
        }
        p++;
    }

    if(i == 0)
    {
        *d = 0;
        return HTTP_TRUE;
    }

    if(i >= 10 && strncmp(s, "4294967295", i) > 0)
    {
        return HTTP_FALSE;
    }

    p = s;
    while(i > 0)
    {
        n = n*10;
        n += *p - '0';
        i--;
        p++;
    }
    *d = n;
    return HTTP_TRUE;
}

/* hex string to digit */
int TOOL_hexatosize(const char *s, size_t *d)
{
    int i = 0;
    size_t n = 0;
    const char *p = s;

    while(*p != 0 )
    {
        if(*p <= '9' && *p >= '0' ||
            *p >= 'a' && *p <= 'f' ||
            *p >= 'A' && *p <= 'F')
        {
            i++;
        }
        else
        {
            break;
        }
        p++;
    }

    if(i == 0)
    {
        *d = 0;
        return HTTP_TRUE;
    }

    
    if(i>8)
    {
        return HTTP_FALSE;
    }
    p = s;
    while(i > 0)
    {
        n = n*16;
        if(*p >= '0' && *p <='9')
        {
            n+=*p-'0';
        }
        else if(*p >='a' && *p <='f')
        {
            n+=*p-'a'+10;
        }
        else
        {
            n+=*p-'A'+10;
        }
        i--;
        p++;
    }
    *d = n;
    return HTTP_TRUE;
}

/* ignore case , strstr */
char *TOOL_strcasestr(const char *s1, const char *s2)
{
	int l1, l2, i;
	char c1, c2;

	l2 = strlen(s2);
	if (!l2)
	{
		return (char *)s1;
	}
	l1 = strlen(s1);
	while (l1 >= l2) {
		l1--;
		for(i=0; i<l2; i++)
		{
		    c1 = s1[i];
		    c2 = s2[i];
		    if(c1 == c2) continue;
		    if(c1 >= 'A' && c1 <= 'Z')
		    {
		        c1 = c1 + ('a' - 'A');
		        if(c1 == c2) continue;
		    }
		    else if(c2 >= 'A' && c2 <='Z')
		    {
		        c2 = c2 + ('a' - 'A');
		        if(c1 == c2) continue;
		    }
		    break;
		}
		if(i==l2) return (char*)s1;
		
		s1++;
	}
	return NULL;
}


int mem_append(char** pp, size_t* len, char* append, size_t append_len)
{
    char* tmp = NULL;

    tmp = (char*)malloc(*len + append_len + 1);

    if (tmp == NULL)
    {
        return HTTP_ERR;
    }

    if (*len > 0)
    {
        memcpy(tmp, *pp, *len);
        free(*pp);
    }

    memcpy(tmp + *len, append, append_len);
    tmp[*len + append_len] = '\0';
    *pp = tmp;
    *len = *len + append_len;
    return HTTP_OK;
}

int http_parse_header(HTTP_TRANS* http)
{
    int ret = HTTP_OK;
    char* p = NULL;

    if (strncmp(http->header, "HTTP", 4) != 0)
    {
        error("can't find HTTP at http header first");
        return HTTP_ERR;
    }

    p = strstr(http->header, " ");

    if (p == NULL)
    {
        error("can't find space at http header first");
        return HTTP_ERR;
    }

    p++;

    if (strncmp(p, "200", 3) != 0)
    {
        error("http status code is not 200, it's %c%c%c",
                    *p, *(p + 1), *(p + 2));
        return HTTP_ERR;
    }

    p = TOOL_strcasestr(http->header, "Content-Length:");

    if (p != NULL)
    {
        HTTP_BOOL suc = HTTP_FALSE;
        p += sizeof("Content-Length:") - 1;

        if (*p == ' ')
        {
            p++;
        }

        http->trans_type = TRANS_TYPE_CONTENT_LEN;
        suc = TOOL_atosize(p, &http->content_total);

        if (!suc)
        {
            error("content length string to uint error");
            return HTTP_ERR;
        }
    }
    else
    {
        p = TOOL_strcasestr(http->header, "Transfer-Encoding: chunked");

        if (p == NULL)
        {
            p = TOOL_strcasestr(http->header, "Transfer-Encoding:chunked");
        }

        if (p == NULL)
        {
            error("http header doesn't have Content-Length or Transfer-Encoding");
            return HTTP_ERR;
        }

        http->trans_type = TRANS_TYPE_CHUNKED;
    }

    return HTTP_OK;
}

int http_trans_header(HTTP_TRANS* http, char* buf, size_t len)
{
    char* header_tail = NULL;
    char* content_start = NULL;
    int b_finish = 0;
    int ret = HTTP_OK;

    ret = mem_append(&http->header, &http->header_len, buf, len);
    RET_NOTOK(ret, "mem append error in http_trans_header");

    header_tail = strstr(http->header, DOUBLELRLF);

    if (header_tail == NULL)
    {
        return HTTP_OK;
    }

    http->header[header_tail - http->header] = 0;
    ret = http_parse_header(http);
    RET_NOTOK(ret, "http trans header error");

    http->status = TRANS_STATUS_CONTENT;

    content_start = header_tail + 4;

    if (http->trans_type == TRANS_TYPE_CONTENT_LEN)
    {
        if (http->content_total == 0)
        {
            http->status = TRANS_STATUS_FINISH;
        }
        else
        {
            ret = http_trans_content_len(http, content_start,
                                             http->header_len - (content_start - http->header));
        }
    }
    else
    {
        /* 交汇点需要用到最后的\r\n，以便做统一处理 */
        content_start -= 2;
        http->chunked_status = CHUNKED_STATUS_JOIN;
        ret = http_trans_chunked(http, content_start, http->header_len - (content_start - http->header));
    }

    RET_NOTOK(ret, "trans header error");

    http->header_len = header_tail - http->header;
    return HTTP_OK;

}

int http_trans_content_len(HTTP_TRANS* http, char* buf, size_t len)
{
    int ret = HTTP_OK;

    if (len == 0) { return HTTP_OK; }

    ret = mem_append(&http->content, &http->content_len, buf, len);
    RET_NOTOK(ret, "mem append error in http_trans_content");

    if (http->content_len >= http->content_total)
    {
        http->status = TRANS_STATUS_FINISH;
    }

    return HTTP_OK;
}

int http_trans_join(HTTP_TRANS* http, char* buf, size_t len, size_t* offset)
{
    char cache[HTTP_JOIN_CACHE_MAX_LEN + 1] = {0};
    size_t cache_len = 0;
    HTTP_BOOL suc = HTTP_FALSE;
    HTTP_BOOL bfinish = HTTP_FALSE;
    int ret = HTTP_OK;
    char* tmp = NULL;

    if (len == 0)
    {
        *offset = 0;
        return HTTP_OK;
    }

    if (http->cache_len != 0)
    {
        memcpy(cache, http->join_cache, http->cache_len);
    }

    if (len >= HTTP_JOIN_CACHE_MAX_LEN - http->cache_len)
    {
        memcpy(cache + http->cache_len, buf,
                               HTTP_JOIN_CACHE_MAX_LEN - http->cache_len);
        cache_len = HTTP_JOIN_CACHE_MAX_LEN;
    }
    else
    {
        memcpy(cache + http->cache_len, buf, len);
        cache_len = len + http->cache_len;
    }

    if (cache_len >= 2)
    {
        if (cache[0] != '\r' || cache[1] != '\n')
        {
            error("join format error");
            return HTTP_ERR;
        }

        if (cache_len > 2)
        {
            tmp = strstr(cache + 2, "\r\n");

            if (tmp != NULL)
            {
                bfinish = HTTP_TRUE;
                *offset = tmp + 2 - cache - http->cache_len;
            }
        }

    }

    if (bfinish)
    {
        http->chunked_status = CHUNKED_STATUS_CONTENT;
        suc = TOOL_hexatosize(cache + 2, &http->chunked_total);

        if (!suc)
        {
            error("chunked start string to uint error");
            return HTTP_ERR;
        }
    }
    else if (cache_len == HTTP_JOIN_CACHE_MAX_LEN)
    {
        error("chunked join length > HTTP_JOIN_CACHE_MAX_LEN, but format is error");
        return HTTP_ERR;
    }
    else
    {

        memcpy(http->join_cache, cache, cache_len);
        http->cache_len = cache_len;
    }

    return HTTP_OK;

}

int http_trans_chunked_content(HTTP_TRANS* http, char* buf, size_t len, size_t* offset)
{
    size_t cpy_len = 0;
    int ret = HTTP_OK;

    if (len >= http->chunked_total - http->chunked_len)
    {
        cpy_len = http->chunked_total - http->chunked_len;
    }
    else
    {
        cpy_len = len;
    }

    ret = mem_append(&http->content, &http->content_len, buf, cpy_len);
    RET_NOTOK(ret, "mem append error in http trans content chunked");

    http->chunked_len += cpy_len;
    *offset = cpy_len;
    return HTTP_OK;
}

int http_trans_chunked(HTTP_TRANS* http, char* buf_in, size_t len_in)
{
    int finish = HTTP_FALSE;
    int ret = HTTP_OK;
    size_t offset = 0;
    char* buf = buf_in;
    size_t len = len_in;

    while (len > 0)
    {
        if (http->chunked_status == CHUNKED_STATUS_CONTENT)
        {
            ret = http_trans_chunked_content(http, buf, len, &offset);
            RET_NOTOK(ret, "chunked content error");

            if (http->chunked_len == http->chunked_total)
            {
                http->chunked_status = CHUNKED_STATUS_JOIN;
                http->chunked_total = http->chunked_len = http->cache_len = 0;
            }
            else
            {
                break;
            }
        }
        else
        {
            ret = http_trans_join(http, buf, len, &offset);
            RET_NOTOK(ret, "chunked join error");

            if (http->chunked_status == CHUNKED_STATUS_CONTENT)
            {
                if (http->chunked_total == 0)
                {
                    http->status = TRANS_STATUS_FINISH;
		    break;
                }
            }
            else
            {
                break;
            }
        }

        buf += offset;
        len -= offset;
    }

    return HTTP_OK;
}

int http_push_packet(HTTP_TRANS* http, char* buf, size_t len)
{
    int ret = HTTP_OK;

    if (http->status == TRANS_STATUS_HEADER)
    {
        ret = http_trans_header(http, buf, len);
        RET_NOTOK(ret, "trans header error");
    }
    else if (http->status == TRANS_STATUS_CONTENT)
    {
        if (http->trans_type == TRANS_TYPE_CONTENT_LEN)
        {
            ret = http_trans_content_len(http, buf, len);
            RET_NOTOK(ret, "trans content len error");
        }
        else
        {
            ret = http_trans_chunked(http, buf, len);
            RET_NOTOK(ret, "trans chunked error");
        }
    }

    return HTTP_OK;
}

void http_trans_free(HTTP_TRANS* p)
{
    if (p->header != NULL)
    {
        free(p->header);
    }

    if (p->content != NULL)
    {
        free(p->content);
    }

    memset(p, 0, sizeof(HTTP_TRANS));
}


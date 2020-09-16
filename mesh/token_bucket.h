#ifndef __TOKEN_BUCKET_H__
#define __TOKEN_BUCKET_H__

#include <stdbool.h>
#include <stdint.h>


struct token_bucket;


struct token_bucket *token_bucket_new(int tokens_per_second);

bool token_bucket_token_get(struct token_bucket *token_bucket);

#endif // __TOKEN_BUCKET_H__

#include "token_bucket.h"

#include <ell/ell.h>


static const int time_quantum_ms = 1;

struct token_bucket {
	int tokens_per_s;
	float tokens;
	struct l_timeout *tokens_add_timeout;
};



static void tokens_add(struct l_timeout *timeout, void *user_data)
{
	struct token_bucket *token_bucket = user_data;
	float tokens_per_time_quantum =
				(float)token_bucket->tokens_per_s / 1000.;

	l_timeout_remove(timeout);

	if ((token_bucket->tokens + tokens_per_time_quantum) <
						token_bucket->tokens_per_s)
		token_bucket->tokens += tokens_per_time_quantum;

	token_bucket->tokens_add_timeout = l_timeout_create_ms(
				time_quantum_ms, tokens_add, user_data, NULL);
}


struct token_bucket *token_bucket_new(int tokens_per_second)
{
	struct token_bucket *token_bucket = l_new(struct token_bucket, 1);

	token_bucket->tokens_per_s = tokens_per_second;
	token_bucket->tokens = 0.;

	if (token_bucket->tokens_per_s)
		token_bucket->tokens_add_timeout = l_timeout_create_ms(
			time_quantum_ms, tokens_add, token_bucket, NULL);

	return token_bucket;
}


bool token_bucket_token_get(struct token_bucket *token_bucket)
{
	if (!token_bucket->tokens_per_s)
		return true;

	if ((unsigned int)token_bucket->tokens > 0)
	{
		token_bucket->tokens -= 1;
		return true;
	}

	return false;
}

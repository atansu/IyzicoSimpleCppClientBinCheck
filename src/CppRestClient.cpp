//============================================================================
// Name        : CppRestClient.cpp
// Author      : Tansu Akturk
// Version     :
// Copyright   : Your copyright notice
// Description : Rest Api Client in C++, Ansi-style
//============================================================================
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

// Generate SHA1 hash to string input
void SHA1 (char* input, char* output)
{
	unsigned char digest[SHA_DIGEST_LENGTH];

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, input, strlen(input));
	SHA1_Final(digest, &ctx);

	char mdString[SHA_DIGEST_LENGTH*2+1];
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

	sprintf(output, "%s", mdString);
}

//Convert hex string to byte array
int hexstr2byte(const char *hex_str, unsigned char *byte_array, int byte_array_max)
{
    int hex_str_len = strlen(hex_str);
    int i = 0, j = 0;

    // The output array size is half the hex_str length (rounded up)
    int byte_array_size = (hex_str_len+1)/2;

    if (byte_array_size > byte_array_max)
    {
        // Too big for the output array
        return -1;
    }

    if (hex_str_len % 2 == 1)
    {
        // hex_str is an odd length, so assume an implicit "0" prefix
        if (sscanf(&(hex_str[0]), "%1hhx", &(byte_array[0])) != 1)
        {
            return -1;
        }

        i = j = 1;
    }

    for (; i < hex_str_len; i+=2, j++)
    {
        if (sscanf(&(hex_str[i]), "%2hhx", &(byte_array[j])) != 1)
        {
            return -1;
        }
    }

    return byte_array_size;
}

//Encode byte array input string to Base64 format
static const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int Base64encode_len(int len)
{
    return ((len + 2) / 3 * 4) + 1;
}
int Base64encode(char *encoded, const char *string, int len)
{
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    *p++ = basis_64[((string[i] & 0x3) << 4) |
                    ((int) (string[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                    ((int) (string[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
        *p++ = basis_64[((string[i] & 0x3) << 4)];
        *p++ = '=';
    }
    else {
        *p++ = basis_64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}

static const char ApiKey[]		= "sandbox-vdC481XnYamHOdu6pNGviphGRyCjCJVD"; //From Iyzico Sandbox Merchant account
static const char SecretKey[]	= "sandbox-XPA3nddaOKyYLhtKi4SWun0bIPhckApa"; //From Iyzico Sandbox Merchant account
char RandomString []			= "291120160630511684"; //Can be anything

int main(void) {

	char BodyParametersPKI[54];
	char hash_out[41];
	char hash_string[256];
	char BinNumber[7];

	//Get Bin Number request
	memset(BinNumber,0,sizeof(BinNumber));
	printf ("ENTER 6 DIGIT BIN NUMBER?");
	scanf ("%6s", BinNumber);

	//POST method body parameter
	memset(BodyParametersPKI,0,sizeof(BodyParametersPKI));
	sprintf(BodyParametersPKI, "[locale=tr,conversationId=123456789,binNumber=%s]", BinNumber);

	//Combine keys and hash the input string via SHA1
	memset(hash_out,0,sizeof(hash_out));
	memset(hash_string,0,sizeof(hash_string));
	sprintf(hash_string, "%s%s%s%s", ApiKey, RandomString, SecretKey, BodyParametersPKI);
	SHA1(hash_string, hash_out);
	//printf("SHA1_out:%s\n", hash_out); // For Debug Purpose

	//Convert hex string to byte array
	unsigned char byte_array[20];
	hexstr2byte(hash_out, byte_array, sizeof(byte_array));

	//Encode SHA1 hash_out to Base64 format
	int data_length = sizeof(byte_array);
	int encoded_data_length = Base64encode_len(data_length);
	char* base64_string = (char*)malloc(encoded_data_length);
	Base64encode(base64_string, (const char*)byte_array, data_length);
	//printf("Base64_out:%s\n", base64_string); // For Debug Purpose

	//Set Authorization header
	char Authorization[128];
	memset(Authorization,0,sizeof(Authorization));
	sprintf(Authorization, "Authorization:IYZWS %s:%s", ApiKey, base64_string);
	//printf("%s\n", Authorization); // For Debug Purpose

	CURL *curl;
	CURLcode res;

	// Add a body parameter for post request
	char* postthis = (char*) malloc(100);
	sprintf(postthis, "{\"locale\":\"tr\",\"conversationId\":\"123456789\",\"binNumber\":\"%s\"}", BinNumber);
	curl = curl_easy_init();
	if (curl)
	{
		// Add a custom header for post request
		struct curl_slist *chunk = NULL;
		chunk = curl_slist_append(chunk, "Accept:application/json");
		chunk = curl_slist_append(chunk, "x-iyzi-rnd:291120160630511684");
		chunk = curl_slist_append(chunk, "x-iyzi-client-version:iyzipay-dotnet-2.1.9");
		chunk =	curl_slist_append(chunk, Authorization);
		chunk = curl_slist_append(chunk, "Content-Type:application/json");
		res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

		//POST method
		curl_easy_setopt(curl, CURLOPT_URL, "https://sandbox-api.iyzipay.com/payment/bin/check");
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postthis);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long )strlen(postthis));

		res = curl_easy_perform(curl);

		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));

		//Free used memory
		curl_easy_cleanup(curl);
		curl_slist_free_all(chunk);
	}
	return 0;
}


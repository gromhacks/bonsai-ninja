#include <curl/curl.h>
#include <openssl/ssl.h>
void insecure(CURL *curl, SSL_CTX *ctx) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
}

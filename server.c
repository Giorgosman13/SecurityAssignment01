#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

SSL_CTX* InitServerCTX(void) {
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS server context (TLS_server_method)
     * 3. Load CA certificate for client verification
     * 4. Configure SSL_CTX to require client certificate (mutual TLS)
     */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* ssl_m;
    ssl_m = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(ssl_m);

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    int temp = SSL_CTX_load_verify_locations(ctx,"OpenSSL/ca.crt",NULL);
    if (temp == 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    /* TODO:
     * 1. Load server certificate using SSL_CTX_use_certificate_file
     * 2. Load server private key using SSL_CTX_use_PrivateKey_file
     * 3. Check that private key matches the certificate using SSL_CTX_check_private_key
    */
   int temp=SSL_CTX_use_certificate_file(ctx, CertFile, 1);
   if (temp == 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    temp = SSL_CTX_use_PrivateKey_file(ctx, KeyFile, 1);
    if (temp == 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    temp = SSL_CTX_check_private_key(ctx);
    if (temp == 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
}

void ShowCerts(SSL* ssl) {
    /* TODO:
     * 1. Get client certificate (if any) using SSL_get_peer_certificate
     * 2. Print Subject and Issuer names
     */
    X509* cert=NULL;
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL ){
        printf("No client certificate presented.\n");
        return;
    }

    printf("Certificate Subject: %s\n", X509_get_subject_name(cert));
    printf("Certificate Issuer: %s\n", X509_get_issuer_name(cert));
    X509_free(cert);
}

void Servlet(SSL* ssl) {
    char buf[1024] = {0};

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
        return;
    }

    ShowCerts(ssl);

    int bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes <= 0) {
        SSL_free(ssl);
        return;
    }
    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);

    /* TODO:
     * 1. Parse XML from client message to extract username and password
     * 2. Compare credentials to predefined values (e.g., "sousi"/"123")
     * 3. Send appropriate XML response back to client
     */

    
    const char* valid_user= "sousi";
    const char* valid_pass= "123";
    const char* r;

    char* u_start = strstr(buf, "<UserName>");
    char* u_end = strstr(buf, "</UserName>");
    char* username = NULL;

    if (u_start == NULL || u_end == NULL || (u_end - u_start)<0){
        printf("Invalid username strstr");
    }else{
        u_start += strlen("<UserName>");
        size_t len_u =(size_t)(u_end-u_start);
        username = malloc(len_u+1);
        memcpy(username,u_start,len_u);
        username[len_u]='\0';
    }

    char* p_start = strstr(buf, "<Password>");
    char* p_end = strstr(buf, "</Password>");
    char* password=NULL;
    if (p_start == NULL || p_end == NULL || (p_end - p_start)<0){
        printf("Invalid password strstr");
    }else{
        p_start += strlen("<Password>");
        size_t len_p = p_end-p_start;
        password = malloc(len_p+1);
        memcpy(password,p_start,len_p);
        password[len_p]='\0';
    }

    if (username == NULL || password == NULL){
        r = "Invalid Message\n";
        SSL_write(ssl,r,strlen(r));
    }else{
        if (strcmp(username,valid_user)==0 && strcmp(password,valid_pass)==0){
            r= "<Body>\n<Name>sousi.com</Name>\n<year>1.5</year>\n<BlogType>Embedede and c c++</BlogType>\n<Author>John Johny</Author>\n</Body>";
        }else{
            r="Invalid Message\n";
        }
        SSL_write(ssl,r,strlen(r));
    }
    free(username);
    free(password);
    int sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);

    /* TODO:
     * 1. Initialize SSL context using InitServerCTX
     * 2. Load server certificate and key using LoadCertificates
     */
    SSL_CTX *ctx = InitServerCTX();
    LoadCertificates(ctx,"OpenSSL/server.crt","OpenSSL/server.key");
    int server = OpenListener(port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl = SSL_new(ctx);

        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* TODO:
         * 1. Create new SSL object from ctx
         * 2. Set file descriptor for SSL using SSL_set_fd
         * 3. Call Servlet to handle the client
         */
        int temp = SSL_set_fd(ssl,client);
        if (temp == 0) {
            ERR_print_errors_fp(stderr);
            close(client);
            SSL_free(ssl);
        }else{
            Servlet(ssl);
        }
    }
    close(server);
    SSL_CTX_free(ctx);
}

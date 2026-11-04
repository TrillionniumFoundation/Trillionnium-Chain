/* Research-only OpenSSL 3.5+ reference, NOT a Trillionnium production node.
 * A genuine client/server TLS 1.3 mutual authentication + hybrid key share
 * experiment. No consensus, signing-key authority or model Final-use issued.
 *
 * Build: cc -std=c11 -Wall -Wextra -Werror -O2 pq_mtls_probe.c -o pq_mtls_probe -lssl -lcrypto
 * Usage: pq_mtls_probe server|client port cert.pem key.pem ca.pem expected_peer_key_id_hex peer_hostname network_hex genesis_hex profile_hex [X25519MLKEM768|X25519]
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define FAIL_IF(cond, name) do { if (cond) { fprintf(stderr,"REFUSED %s\n", name); goto cleanup; } } while(0)

static int unhex32(const char *s, unsigned char out[32]) {
    if (!s || strlen(s)!=64) return 0;
    for(int i=0;i<32;i++) {
        int hi=s[2*i],lo=s[2*i+1];
        if(hi>='0'&&hi<='9')hi-='0'; else if(hi>='a'&&hi<='f')hi=hi-'a'+10; else return 0;
        if(lo>='0'&&lo<='9')lo-='0'; else if(lo>='a'&&lo<='f')lo=lo-'a'+10; else return 0;
        out[i]=(unsigned char)((hi<<4)|lo);
    }
    return 1;
}
static void hex32(const unsigned char *v, char s[65]) {
    static const char h[]="0123456789abcdef";
    for(int i=0;i<32;i++){s[2*i]=h[v[i]>>4];s[2*i+1]=h[v[i]&15];}s[64]=0;
}
static int peer_key_id(X509 *cert,unsigned char out[32]) {
    static const unsigned char domain[]="TRNM/PoN/PQKey/v1"; /* includes terminating NUL */
    EVP_PKEY *pk = X509_get_pubkey(cert);
    unsigned char *buf=NULL; EVP_MD_CTX *d=NULL; int ok=0;
    if(!pk||!EVP_PKEY_is_a(pk,"ML-DSA-65"))goto cleanup;
    int size=i2d_PUBKEY(pk,&buf);
    if(size<=0||size>10000)goto cleanup;
    d=EVP_MD_CTX_new();
    if(!d||EVP_DigestInit_ex(d,EVP_sha256(),NULL)!=1||
       EVP_DigestUpdate(d,domain,sizeof(domain))!=1||
       EVP_DigestUpdate(d,buf,(size_t)size)!=1||
       EVP_DigestFinal_ex(d,out,NULL)!=1)goto cleanup;
    ok=1;
cleanup:
    EVP_MD_CTX_free(d);OPENSSL_free(buf);EVP_PKEY_free(pk);return ok;
}
static int set_timeout(int fd){
    struct timeval tv={.tv_sec=5,.tv_usec=0};
    return setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv))==0 &&
           setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv))==0;
}
int main(int argc,char **argv){
    SSL_CTX *ctx=NULL;SSL *ssl=NULL;X509 *peer=NULL;EVP_MD_CTX *dig=NULL;
    int fd=-1,listener=-1,return_code=1;
    unsigned char expected_peer[32],actual_peer[32],network[32],genesis[32],profile[32];
    unsigned char export_context[96],export_secret[32],export_tag[32];
    char peer_hex[65],tag_hex[65];
    static const char label[]="EXPORTER-TRNM-PQ-P2P-v1";
    static const char tag_domain[]="TRNM/PQPeerChannelTag/v1";
    if(argc!=12){fprintf(stderr,"REFUSED arguments\n");return 2;}
    int is_server=strcmp(argv[1],"server")==0;
    if(!is_server && strcmp(argv[1],"client")!=0) return 2;
    char *end=NULL;long port=strtol(argv[2],&end,10);
    if(!end||*end||port<1||port>65535) return 2;
    if(!unhex32(argv[6],expected_peer)||!unhex32(argv[8],network)||
       !unhex32(argv[9],genesis)||!unhex32(argv[10],profile)){
       fprintf(stderr,"REFUSED canonical identity\n");return 2;
    }
    memcpy(export_context,network,32);memcpy(export_context+32,genesis,32);memcpy(export_context+64,profile,32);
    ctx=SSL_CTX_new(TLS_method());FAIL_IF(!ctx,"ctx");
    FAIL_IF(SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION)!=1||
            SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION)!=1,"tls_version");
    FAIL_IF(SSL_CTX_set1_groups_list(ctx,argv[11])!=1,"group_config");
    FAIL_IF(SSL_CTX_use_certificate_chain_file(ctx,argv[3])!=1||
            SSL_CTX_use_PrivateKey_file(ctx,argv[4],SSL_FILETYPE_PEM)!=1||
            SSL_CTX_check_private_key(ctx)!=1,"local_certificate");
    FAIL_IF(SSL_CTX_load_verify_locations(ctx,argv[5],NULL)!=1,"trust_root");
    SSL_CTX_set_verify(ctx,is_server?(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT):SSL_VERIFY_PEER,NULL);
    SSL_CTX_set_verify_depth(ctx,2);
    if(is_server){
      listener=socket(AF_INET,SOCK_STREAM,0);FAIL_IF(listener<0,"listener");
      struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons((unsigned short)port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
      FAIL_IF(bind(listener,(void*)&addr,sizeof(addr))!=0||listen(listener,1)!=0,"bind");
      printf("READY\n");fflush(stdout);
      fd=accept(listener,NULL,NULL);FAIL_IF(fd<0,"accept");
    } else {
      fd=socket(AF_INET,SOCK_STREAM,0);FAIL_IF(fd<0,"client_socket");
      struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons((unsigned short)port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
      FAIL_IF(connect(fd,(void*)&addr,sizeof(addr))!=0,"connect");
    }
    FAIL_IF(!set_timeout(fd),"socket_timeout");
    ssl=SSL_new(ctx);FAIL_IF(!ssl,"ssl");
    FAIL_IF(SSL_set_fd(ssl,fd)!=1,"fd");
    if(!is_server){
      FAIL_IF(SSL_set_tlsext_host_name(ssl,argv[7])!=1,"sni");
      FAIL_IF(SSL_set1_host(ssl,argv[7])!=1,"hostname_config");
    }
    FAIL_IF((is_server?SSL_accept(ssl):SSL_connect(ssl))!=1,"handshake");
    FAIL_IF(SSL_version(ssl)!=TLS1_3_VERSION,"protocol_downgrade");
    const char *group=SSL_get0_group_name(ssl);
    FAIL_IF(!group||strcmp(group,"X25519MLKEM768")!=0,"classical_group_downgrade");
    FAIL_IF(SSL_get_verify_result(ssl)!=X509_V_OK,"certificate_validation");
    peer=SSL_get1_peer_certificate(ssl);FAIL_IF(!peer,"mutual_certificate_required");
    FAIL_IF(!peer_key_id(peer,actual_peer),"peer_not_mldsa65");
    FAIL_IF(CRYPTO_memcmp(actual_peer,expected_peer,32)!=0,"peer_id_pin");
    FAIL_IF(SSL_export_keying_material(ssl,export_secret,sizeof(export_secret),
            label,strlen(label),export_context,sizeof(export_context),1)!=1,"tls_exporter");
    dig=EVP_MD_CTX_new();FAIL_IF(!dig,"digest_context");
    FAIL_IF(EVP_DigestInit_ex(dig,EVP_sha256(),NULL)!=1||
       EVP_DigestUpdate(dig,tag_domain,sizeof(tag_domain))!=1||
       EVP_DigestUpdate(dig,export_secret,sizeof(export_secret))!=1||
       EVP_DigestFinal_ex(dig,export_tag,NULL)!=1,"exporter_digest");
    OPENSSL_cleanse(export_secret,sizeof(export_secret));
    if(is_server){
       unsigned char ping[4];
       FAIL_IF(SSL_read(ssl,ping,sizeof(ping))!=4||memcmp(ping,"PING",4)!=0,"request_data");
       FAIL_IF(SSL_write(ssl,"PONG",4)!=4,"response_data");
    }else{
       unsigned char pong[4];
       FAIL_IF(SSL_write(ssl,"PING",4)!=4,"request_data");
       FAIL_IF(SSL_read(ssl,pong,sizeof(pong))!=4||memcmp(pong,"PONG",4)!=0,"response_data");
    }
    hex32(actual_peer,peer_hex);hex32(export_tag,tag_hex);
    printf("{\"authenticated\":true,\"mtls\":true,\"protocol\":\"TLS1.3\",\"group\":\"X25519MLKEM768\",\"peer_key_id\":\"%s\",\"channel_tag\":\"%s\"}\n",peer_hex,tag_hex);
    return_code=0;
cleanup:
    OPENSSL_cleanse(export_secret,sizeof(export_secret));
    EVP_MD_CTX_free(dig);X509_free(peer);SSL_free(ssl);SSL_CTX_free(ctx);
    if(fd>=0)close(fd);
    if(listener>=0)close(listener);
    return return_code;
}

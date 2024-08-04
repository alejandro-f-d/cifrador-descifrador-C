/*Cargamos las librerias principales*/
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
RSA *cargar_clave_privada(FILE *f);
void descifrar_clave_iv(FILE *f, EVP_PKEY *pkey);
void descifrar_simetricamente(unsigned char *cadena, int longitud);
void descifrar_documento(FILE *fichero_descifrar, RSA *clavePrivadaobtenida);
int ppaldescifrado(char * dirclaveprivada, char *dirfichero);
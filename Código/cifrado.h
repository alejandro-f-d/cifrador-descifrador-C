/*Cargamos las librerias principales*/
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
void inicializarEntorno();
RSA *cargarClavePublica(FILE *f);
void generar_iv_key_aleatorio();
void cifrarClaveSimetrica(RSA *clavePublica, unsigned char *claveSimetrica, size_t *longitudCif, int quehago);
void escribirFichero(FILE *f, unsigned char *cadena, size_t tamano);
void cifrarconClaveSimetrica(char *cadena_plana, size_t longitudCadenaPlana);
void cifrarDoc(FILE *f);
int ppal_cifrado(char * clave_privada, char * fichero_cifrar);
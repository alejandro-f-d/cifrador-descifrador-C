#include "descifrado.h"
#include "cifrado.h"
/*Definiciones de arrays importantes*/

/*
 * Tamaños para diferentes bits de clave
 * 16 for a 128-bit key
 * 24 for a 192-bit key
 * 32 for a 256-bit key
 */

unsigned char iv_d[AES_BLOCK_SIZE]; // 16 bytes
unsigned char key_simetrica_d[32];  // 256 bit key
FILE *fichero_descifrado;

/*
 * Función encargada de cargar la clave privada
 */

RSA *cargar_clave_privada(FILE *f)
{
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (!pkey)
    {
        fprintf(stderr, "Error cargando clave privada: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa)
    {
        fprintf(stderr, "Error obteniendo clave RSA: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(pkey);
        return NULL;
    }

    EVP_PKEY_free(pkey);
    return rsa;
}

/*
 * Función encargada de descifrar la clave simétrica y el IV.
 */
void descifrar_clave_iv(FILE *f, EVP_PKEY *pkey)
{
    int longClavesimetrica;
    unsigned char clave_sim_cifrada[512], iv_cifrada[512];
    /*
     * Necesitamos un ciclo que el primero lo que hará es cargar la clave_sim cifrada.
     * mientras que el segundo lo que hará es cargar el IV.
     */
    if (fread(clave_sim_cifrada, sizeof(char), 512, f) != 512)
    {
        exit(-1);
    }
    if (fread(iv_cifrada, sizeof(char), 512, f) != 512)
    {
        exit(-2);
    }

    RSA_private_decrypt(512, clave_sim_cifrada, key_simetrica_d, pkey, RSA_PKCS1_OAEP_PADDING);

    RSA_private_decrypt(512, iv_cifrada, iv_d, pkey, RSA_PKCS1_OAEP_PADDING);
}

/*
 * Una vez se tiene la clave simétrica y el IV debemos aplicar el algoritmo de descifrado para claves simétricas.
 */

void descifrar_simetricamente(unsigned char *cadena, int longitud)
{
    unsigned char *cadenaDescifrada = calloc(sizeof(char), 1000);
    int longitudCadenaDescifrada;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_simetrica_d, iv_d);
    EVP_DecryptUpdate(ctx, cadenaDescifrada, &longitudCadenaDescifrada, cadena, longitud);
    EVP_DecryptFinal_ex(ctx, cadenaDescifrada + longitudCadenaDescifrada, &longitudCadenaDescifrada);
    EVP_CIPHER_CTX_free(ctx);
    fwrite(cadenaDescifrada, sizeof(char), strlen(cadenaDescifrada), fichero_descifrado);

    free(cadenaDescifrada);
}

void descifrar_documento(FILE *fichero_descifrar, RSA *clavePrivadaobtenida)
{
    int longitudLeido;
    unsigned char cadenaDescifrar[32];
    descifrar_clave_iv(fichero_descifrar, clavePrivadaobtenida);
    while ((longitudLeido = fread(cadenaDescifrar, sizeof(char), 32, fichero_descifrar)) != 0)
    {
        descifrar_simetricamente(cadenaDescifrar, longitudLeido);
    }
}

int ppaldescifrado(char * dirclaveprivada, char *dirfichero)
{
    inicializarEntorno();
    FILE *clavePrivada = fopen(dirclaveprivada, "r");
    FILE *ficheroCifrado = fopen(dirfichero, "r");
    if(clavePrivada == NULL || ficheroCifrado == NULL){
        fprintf(stderr, "Error al acceder al fichero.\n");
        exit(-10);
    }
    RSA *clavePrivadaobtenida = cargar_clave_privada(clavePrivada);
    fichero_descifrado = fopen("descifradoB.txt", "w");
    descifrar_documento(ficheroCifrado, clavePrivadaobtenida);
    fclose(ficheroCifrado);
    fclose(fichero_descifrado);
    fclose(clavePrivada);
}
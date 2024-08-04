#include "cifrado.h"

/*Definiciones de arrays importantes*/

/*
 * Tamaños para diferentes bits de clave
 * 16 for a 128-bit key
 * 24 for a 192-bit key
 * 32 for a 256-bit key
 */

unsigned char iv[AES_BLOCK_SIZE];     // 16 bytes
unsigned char key_simetrica[32];      // 256 bit key
unsigned char *key_simetrica_cifrada; /* El tamaño se asigna con un calloc.*/
unsigned char *iv_Cifrado;

FILE *fich_encriptado;

/*Cargamos funciones necesarias para el funcionamiento del ssl */
void inicializarEntorno()
{
    OPENSSL_init_crypto(0, NULL);
    OPENSSL_init_ssl(0, NULL);
}

/*Cargamos la clave pública desde un fichero*/

RSA *cargarClavePublica(FILE *f)
{
    RSA *rsa_keypub = RSA_new();
    if (rsa_keypub == NULL)
    {
        exit(-1);
    }
    if (!PEM_read_RSA_PUBKEY(f, &rsa_keypub, NULL, NULL))
    {
        fprintf(stderr, "Error cargando clave pública: %s\n", ERR_error_string(ERR_get_error(), NULL));
        RSA_free(rsa_keypub);
        return NULL;
    }
    return rsa_keypub;
}

void generar_iv_key_aleatorio()
{
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1)
    {
        fprintf(stderr, "Error generando un IV");
        exit(-2);
    }
    if (RAND_bytes(key_simetrica, 32) != 1)
    {
        fprintf(stderr, "Error generando la key simétrica");
        exit(-3);
    }
}

void cifrarClaveSimetrica(RSA *clavePublica, unsigned char *claveSimetrica, size_t *longitudCif, int quehago)
{
    if (clavePublica == NULL)
    {
        fprintf(stderr, "Error: clave pública no cargada\n");
        return;
    }
    size_t longitudClave = (quehago == 0) ? 32 : AES_BLOCK_SIZE;
    *longitudCif = RSA_size(clavePublica);
    if (quehago == 0)
    {
        key_simetrica_cifrada = calloc(*longitudCif, sizeof(char));
        if (RSA_public_encrypt(longitudClave, claveSimetrica, key_simetrica_cifrada, clavePublica, RSA_PKCS1_OAEP_PADDING) != *longitudCif)
        {
            exit(-4);
        }
    }
    else
    {
        iv_Cifrado = calloc(*longitudCif, sizeof(char));
        if (RSA_public_encrypt(longitudClave, claveSimetrica, iv_Cifrado, clavePublica, RSA_PKCS1_OAEP_PADDING) != *longitudCif)
        {
            exit(-5);
        }
    }
}

void escribirFichero(FILE *f, unsigned char *cadena, size_t tamano)
{
    fwrite(cadena, sizeof(char), tamano, f);
}

/*
 * A continuación se va a desarrollar la función que va a cifrar con clave simetrica.
 * Vamos a leer de 16 bytes  que es con lo que funciona el cifrado.
 */

void cifrarconClaveSimetrica(char *cadena_plana, size_t longitudCadenaPlana)
{
    unsigned char cadenaCifrada[5000]; /*Tamaño excesivo para que entre la cadena cifrada.*/
    size_t longitudCifrado;
    /*Iniciamos el contexto de cifrado*/
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    /*Inicializar el contexto de cifrado*/
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_simetrica, iv);
    /*Cifrar datos:
        Tamaño de la cadena cifrada = (Tamaño de la cadena de texto plano + 15) / 16 * 16
    */

    EVP_EncryptUpdate(ctx, cadenaCifrada, &longitudCifrado, cadena_plana, longitudCadenaPlana);

    /*Finalizacion del cifrado:*/
    int final_len;
    EVP_EncryptFinal_ex(ctx, cadenaCifrada + longitudCifrado, &final_len);
    longitudCifrado += final_len;

    /*Terminar la cadena cifrada con un nulo*/
    cadenaCifrada[longitudCifrado] = '\0';

    /*Liberamos el contexto de cifrado*/
    EVP_CIPHER_CTX_free(ctx);
    escribirFichero(fich_encriptado, cadenaCifrada, longitudCifrado);
}

void cifrarDoc(FILE *f)
{
    char cadena_a_cifrar[16];
    int longitudCad;
    while ((longitudCad = fread(cadena_a_cifrar, sizeof(char), 16, f)) != 0)
    {
        cifrarconClaveSimetrica(cadena_a_cifrar, longitudCad);
    }
}

int ppal_cifrado(char * clave_privada, char * fichero_cifrar)
{
    unsigned char *claveIV;
    size_t longuitudCifradoClave, longitudCifradoIV;
    FILE *f = fopen(clave_privada, "r");
    fich_encriptado = fopen("encriptado.txt", "w");
    if (f == NULL)
    {
        return -6;
    }
    RSA *clavePublica = cargarClavePublica(f);
    fclose(f);
    if (clavePublica == NULL)
    {
        return -7;
    }
    generar_iv_key_aleatorio();

    cifrarClaveSimetrica(clavePublica, key_simetrica, &longuitudCifradoClave, 0);

    cifrarClaveSimetrica(clavePublica, iv, &longitudCifradoIV, 1);

    /*
     * Ahora lo que se va a hacer es escribir tanto la clave simétrica cifrada
     * como el iv en el archivo:
     */

    escribirFichero(fich_encriptado, key_simetrica_cifrada, longuitudCifradoClave);
    escribirFichero(fich_encriptado, iv_Cifrado, longitudCifradoIV);
    FILE *g = fopen(fichero_cifrar, "r");
    if(g == NULL){
        fprintf(stderr, "Se produjo un error con el fichero a cifrar.");
        exit(-10);
    }
    cifrarDoc(g);

    RSA_free(clavePublica);
    fclose(g);
    fclose(fich_encriptado);
    remove(fichero_cifrar);
    return 0;
}
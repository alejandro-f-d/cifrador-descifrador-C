#include "cifrado.h"
#include "descifrado.h"
#include <stdio.h>
#include <dirent.h>
void analizarArchivos(char *direccion, int quehago, char * dir_clave)
{
  struct dirent *entry;
  DIR *dir = opendir(direccion);
  /*printf("Dirección a mirar '%s'\n", direccion);*/

  if (dir == NULL)
  {
    fprintf(stderr, "Error con la dirección '%s'\n", direccion);
    return;
  }
  while ((entry = readdir(dir)) != NULL)
  {
    if (entry->d_type == 4 && strcmp(entry->d_name, ".") != 0 &&
        strcmp(entry->d_name, "..") != 0)
    {
      char dir_path[strlen(direccion) + strlen(entry->d_name) + 2];
      strcpy(dir_path, direccion);
      strcat(dir_path, "/");
      strcat(dir_path, entry->d_name);
      analizarArchivos(dir_path, quehago, dir_clave);
    }
    else if (entry->d_type == 8)
    {
      char dir_path[strlen(direccion) + strlen(entry->d_name) + 2];
      strcpy(dir_path, direccion);
      strcat(dir_path, "/");
      strcat(dir_path, entry->d_name);
      (quehago == 0) ? cifrar(dir_clave, dir_path) : descifrar(dir_clave, dir_path);
      
    }
  }
  closedir(dir);
}
void byteToBinary(unsigned char byte, char *binaryStr)
{
  /*Debemos convertir cada byte del archivo a binario para posteriormente aplicarle la clave pública.*/
  int i;
  for (i = 7; i >= 0; i--)
  {
    binaryStr[7 - i] = (byte & (1 << i)) ? '1' : '0';
  }
  binaryStr[8] = '\0';
}
unsigned char binaryToByte(const char *binaryString)
{
  unsigned char byteValue = 0;
  unsigned int i = 0;
  for (i = 0; i < 8; i++)
  {
    if (binaryString[i] == '1')
    {
      byteValue |= (1 << (7 - i));
    }
    else if (binaryString[i] != '0')
    {
      fprintf(stderr,
              "Error: Cadena binaria contiene caracteres no válidos.\n");
      exit(EXIT_FAILURE);
    }
  }

  return byteValue;
}

void cifrar(char *dir_clave, char *dir_fichero)
{

  FILE *fichero_en_binario = fopen("fichero_bin", "w");
  FILE *fichero_cifrar = fopen(dir_fichero, "r");
  if (fichero_cifrar == NULL)
  {
    fprintf(stderr, "fichero a cifrar error");
    return -1;
  }
  int tam;
  char linea[1024];

  while ((tam = fread(linea, sizeof(char), 1024, fichero_cifrar)) != 0)
  {
    unsigned int i;
    for (i = 0; i < tam; ++i)
    {
      char cadena[8];
      byteToBinary(linea[i], cadena);
      fwrite(cadena, sizeof(char), 8, fichero_en_binario);
    }
  }
  fclose(fichero_cifrar);
  fclose(fichero_en_binario);
  
  ppal_cifrado(dir_clave, "fichero_bin");
  char *nombre = calloc(sizeof(char), strlen(dir_fichero) + 5);
  /*
   * 4 para el .env y uno para el finalizador.
   */
  strcpy(nombre, dir_fichero);
  strcat(nombre, ".env");
  rename("encriptado.txt", nombre);
  remove(dir_fichero);
}

void descifrar(char *dir_clave, char *dir_fichero)
{
  FILE *archivoBin;
  FILE *archivoCarac = fopen("descifrado", "w");
  int tam;
  char cadena[8];
  
  ppaldescifrado(dir_clave, dir_fichero);
  
  archivoBin = fopen("descifradoB.txt", "r");
  if (archivoBin == NULL)
  {
    fprintf(stderr, "Error al abrir el archivo");
    exit(-10);
  }
  while ((tam = fread(cadena, sizeof(char), 8, archivoBin)) != 0)
  {
    /*printf("Tam: %d\n", tam);*/
    cadena[0] = binaryToByte(cadena);
    fwrite(cadena, sizeof(char), 1, archivoCarac);
  }
  fclose(archivoBin);
  fclose(archivoCarac);
  
  char *nombre = calloc(sizeof(char), strlen(dir_fichero));
  strncpy(nombre, dir_fichero, strlen(dir_fichero) - 4);
  rename("descifrado", nombre);
  remove(dir_fichero);
  remove("descifradoB.txt");
}

int main()
{
  int operacion;
  char dir_clave[1500], dir_fichero[1500];
  printf("====Inicio del programa====\n ¿Qué quieres hacer?\n1.Cifrar\n2.Descifrar.\n3.Cifrar recursivo.\n4.Descifrar recursivo.\n");
  scanf("%d", &operacion);
  if (operacion == 1)
  {
    printf("Dirección de la clave pública:\n");
    scanf("%s", dir_clave);
    printf("Dirección del fichero a realizar el cifrado:\n");
    scanf("%s", dir_fichero);
    cifrar(dir_clave, dir_fichero);
  }
  else if (operacion == 2)
  {
    printf("Dirección de la clave privada: \n");
    scanf("%s", dir_clave);
    printf("Dirección del fichero a realizar el descifrado :\n");
    scanf("%s", dir_fichero);
    descifrar(dir_clave, dir_fichero);
  } else if (operacion == 3){
    printf("Dirección de la clave pública:\n");
    scanf("%s", dir_clave);
    printf("Dirección del fichero a realizar el cifrado de manera recursiva:\n");
    scanf("%s", dir_fichero);
    analizarArchivos(dir_fichero, 0, dir_clave);
  }else if(operacion == 4){
    printf("Dirección de la clave privada: \n");
    scanf("%s", dir_clave);
    printf("Dirección del fichero a realizar el descifrado de manera recursiva:\n");
    scanf("%s", dir_fichero);
    analizarArchivos(dir_fichero, 1, dir_clave);
  }
  return 0;
}

#include <stdio.h>
#include <string.h>

 
int main (int argc, char *argv[])
{
  char buffer[4];
  strcpy(buffer,argv[1]);
 
  FILE * ptrFile = fopen ( "/proc/Tcp_block_port" , "wb" );
  size_t w_s=fwrite(buffer , 1 , sizeof(buffer) , ptrFile ); // записать в файл содержимое буфера
  printf("Записано %ld байт   %s\n",w_s,buffer);
  fclose (ptrFile);
  return 0;
}

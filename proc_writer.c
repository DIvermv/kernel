#include <stdio.h>
#include <string.h>

/* Для передачи в ядро номера TCP порта
 * вызвать программу с правами администратора
 * В качестве параметра передать номер порта
 */
 
int main (int argc, char *argv[])
{
FILE * ptrFile; 
  if((ptrFile = fopen ( "/proc/Tcp_block_port" , "w" ))!=NULL)
  {
  size_t w_s=fwrite(argv[1] , sizeof(argv[1]) ,1, ptrFile ); // записать в файл содержимое буфера
  printf("Записано %ld блок размером %li   %s\n",w_s,sizeof(argv[1]),argv[1]);
  fflush(ptrFile);
  fclose (ptrFile);
  } 

  return 0;
}

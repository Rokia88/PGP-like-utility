#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#define SYM_KEY_SIZE 16 //16 bytes
#define SEED_FILE_NAME_SIZE 20

unsigned char* encrypt (char *message,  RSA *cli_pub_key, long *buffer_size)
{
	unsigned char *encrypted =  (unsigned char *)malloc(RSA_size(cli_pub_key));
	*buffer_size = RSA_public_encrypt(strlen(message), (unsigned char *) message, encrypted, cli_pub_key, RSA_PKCS1_PADDING);
	if(*buffer_size == -1)
	{
		fputs("\n Impossible de chiffrer. \n",stderr);
		exit(-1);
	}
	return encrypted;
}

RSA* load_pubkey(char *key_file_name)
{
	FILE *keyfile;
	keyfile = fopen(key_file_name, "r");
	if(keyfile == NULL)
	{
		fputs("Echec du chargement de la clef!\n",stderr);
		exit(-1);
	}

	//Retrieve the size of the file
	struct stat file_status;
	char *file_buffer = NULL;

	stat(key_file_name, &file_status);
	long file_size = file_status.st_size;
	file_buffer = (char *)malloc(file_size); //Allocate memory for the buffer using the size of the file
	fread(file_buffer,1,file_size,keyfile);
	fclose(keyfile);

        BIO *bp = BIO_new_mem_buf(file_buffer,-1);
        RSA *pub_key = PEM_read_bio_RSA_PUBKEY(bp,0,0,0);
        BIO_free(bp);

	free(file_buffer);
	return pub_key;
}

void pgp_encrypt(char *file_to_encrypt_name,char *key_file_name)
{

	//génération de la clé symétrique
	unsigned char *key = (char *)malloc(sizeof(char)*SYM_KEY_SIZE);
	char filename[SEED_FILE_NAME_SIZE]; 
	const char *rand_file_name = RAND_file_name(filename, SEED_FILE_NAME_SIZE);//The seed file is $RANDFILE if that environment variable is set, $HOME/.rnd otherwise. If $HOME is not set either, 													or num is too small for the path name, an error occurs.
	int rslt = RAND_load_file(rand_file_name, -1);
	RAND_bytes(key, SYM_KEY_SIZE);
	/*int i;
	printf("AES key:\n");
	for (i= 0; i< SYM_KEY_SIZE; ++i) {
		if ( ! (i % SYM_KEY_SIZE) && i ) printf("\n");
		printf("%02x ", *(key+i));
	}*/
	RAND_cleanup();
	
	//charger la clé publique RSA
	RSA *pub_key  = load_pubkey(key_file_name);

	//chiffrer la clé symétrique avec la clé publique 
	long enc_message_length = 0;
	unsigned char *encrypted = encrypt(key, pub_key, &enc_message_length);
	
	//mettre la clé symétrique chiffrée dans le fichier aes.key
	FILE *file;
	file = fopen("aes.key", "wb");
	fwrite(encrypted,1,enc_message_length,file);
	fclose(file);

	//lire le contenu du fichier qu'on veut chiffrer et le mettre dans une chaine de caractère
	file = fopen(file_to_encrypt_name, "rb");
	if(file == NULL)
	{
		fputs("Echec du chargement de fichier!\n",stderr);
		exit(-1);
	}
	struct stat file_status;
	char *file_buffer = NULL;
	stat(file_to_encrypt_name, &file_status);
	long file_size = file_status.st_size;
	file_buffer = (char *)malloc(file_size); 
	fread(file_buffer,1,file_size,file);
	fclose(file);
	
	//chiffrer le fichier avec la clé symétrique 
	unsigned int message_len = strlen((char*)file_buffer)+1;
	unsigned int encrypt_len = (message_len % AES_BLOCK_SIZE == 0) ? message_len : (message_len / AES_BLOCK_SIZE +1) * AES_BLOCK_SIZE;
	AES_KEY aes;
	int ret = AES_set_encrypt_key(key,SYM_KEY_SIZE*8,&aes);
	unsigned char iv[AES_BLOCK_SIZE];
  	memset(iv,0,AES_BLOCK_SIZE);
	char c[encrypt_len];
  	AES_cbc_encrypt(file_buffer, c, encrypt_len, &aes, iv, AES_ENCRYPT);
	
	//mettre le contenu chiffré dans le fichier file_to_encrypt_name.enc
	char *encrypted_file_name = strrchr(file_to_encrypt_name,'.');
	if(encrypted_file_name!= NULL)
	{
		*encrypted_file_name = '\0';
	}
	
	strcat(file_to_encrypt_name,".enc");
	file = fopen(file_to_encrypt_name, "wb");
	fwrite(c,1,encrypt_len,file);
	fclose(file);
	

}
int main(int argc, char* argv[]) {
  
printf ("***./prog file_to_encrypt_path public_key_file_path *** \n");
  if(argc < 3)
	{
		printf("nombre d'arguments insuffisants\n");
		exit(-1);
	}
   
  char *name = argv[1];
  char *pub_key = argv[2];	
  pgp_encrypt(name,pub_key);

  return 0;
}

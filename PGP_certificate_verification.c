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
 #include <openssl/sha.h>

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

void certificate_verify(char *identity,char *key_file_name,char *client_certificate, char *client_pub_key)
{
	//charger la clé publique de l'autorité
	RSA *pub_key  = load_pubkey(key_file_name);

	//charger la clé publique du client
	FILE* cl_pub_key = fopen(client_pub_key,"r");
	unsigned char* cl_pub_key_string = NULL;
	char *file_buffer = NULL;
	if(cl_pub_key == NULL)
	{
		fputs("Echec du chargement de fichier!\n",stderr);
		exit(-1);
	}
	struct stat file_status;
	stat(client_pub_key, &file_status);
	long file_size = file_status.st_size;
	cl_pub_key_string = (char *)malloc(file_size);
	file_buffer = (char *)malloc(file_size); 
	fread(file_buffer,1,file_size,cl_pub_key);
	strcpy(cl_pub_key_string,file_buffer);
	fclose(cl_pub_key);

	//ouvrir le certificat qui a le nom 'identity.cert'
	FILE *certificate = fopen(client_certificate,"rb");
	if(certificate == NULL)
	{
		fputs("Echec du chargement de fichier!\n",stderr);
		exit(-1);
	}

	//récupérer l'identité
	unsigned char* name= (unsigned char *)malloc(sizeof(char)*strlen(identity));
	fread(name,1,strlen(identity),certificate);

	//récupérer la clé publique
	fread(file_buffer,1,strlen(cl_pub_key_string),certificate);

	//récupérer la signature 
	unsigned char* signature = (unsigned char *)malloc(sizeof(char)*RSA_size(pub_key));
	fread(signature,1,RSA_size(pub_key),certificate);
	
	//hasher la clé publique du client
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(cl_pub_key_string, strlen(cl_pub_key_string), hash);
	/*int i;
	for (i= 0; i< SHA_DIGEST_LENGTH; ++i) {
		if ( ! (i % SHA_DIGEST_LENGTH) && i ) printf("\n");
		printf("%02x ", hash[i]);
	}*/

	//vérifier la signature
	int rslt = RSA_verify(NID_sha1, hash,SHA_DIGEST_LENGTH, signature, RSA_size(pub_key), pub_key);
	if(rslt==1)
	{
		printf("La clé publique que vous avez correspond bien à celle de %s\n",identity);
	}
	fclose(certificate);
}

int main(int argc, char* argv[]) {
  
printf ("***./prog client_name client_certificate_path client_public_key_path*** \n");
  if(argc < 4)
	{
		printf("nombre d'arguments insuffisants\n");
		exit(-1);
	}
   
  char *identity = argv[1];
  char *client_certificate = argv[2];
  char *client_pub_key = argv[3];
  char *pub_key = "public_autority.key";	
  certificate_verify(identity,pub_key,client_certificate,client_pub_key);

  return 0;
}

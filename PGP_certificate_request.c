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

RSA* load_pubkey(char *key_file_name,unsigned char** key)
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
	*key = (char *)malloc(file_size);
	fread(file_buffer,1,file_size,keyfile);
	strcpy(*key,file_buffer); // récupérer la clé sous la forme d'une chaine de caractère
	fclose(keyfile);

        BIO *bp = BIO_new_mem_buf(file_buffer,-1);
        RSA *pub_key = PEM_read_bio_RSA_PUBKEY(bp,0,0,0);
        BIO_free(bp);

	free(file_buffer);
	return pub_key;
}


RSA* load_privkey(char *key_file_name)
{
        FILE *priv_key = fopen(key_file_name,"r");
	if(priv_key == NULL)
	{
		fputs("Echec du chargement de fichier!\n",stderr);
		exit(-1);
	}
        RSA *rsa_priv_key = PEM_read_RSAPrivateKey(priv_key,NULL,NULL,NULL);
	fclose(priv_key);
	return rsa_priv_key;
}

void certificate_request(char *identity,char *key_file_name)
{
	//charger la clé publique du client
	unsigned char* pub_key_client_string;
	RSA *pub_key_client  = load_pubkey(key_file_name,&pub_key_client_string);

	//créer le fichier de certification pour le client identifié par 'identity'
	FILE *certificate_file;
	char *identity_dup = (char*)malloc(strlen(identity));
	strcpy(identity_dup,identity);
	strcat(identity,".cert");
	certificate_file = fopen(identity, "rb");
	if(certificate_file == NULL)
	{
	   certificate_file = fopen(identity, "wb");
	}
	else
	{
		printf("veuillez choisir un autre identifiant\n");
		exit(-1);
	}

	//créer le certificat = hasher et signer la clef publique du client
	//calculer le hash de la clé publique du client	
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(pub_key_client_string, strlen(pub_key_client_string), hash);
	/*int i;
	for (i= 0; i< SHA_DIGEST_LENGTH; ++i) {
		if ( ! (i % SHA_DIGEST_LENGTH) && i ) printf("\n");
		printf("%02x ", hash[i]);
	}*/

	//signer le hash de la clé publique du client
	RSA *rsa_priv_key  = load_privkey("private_autority.key");
	unsigned char* signature = (unsigned char *)malloc(RSA_size(rsa_priv_key));
	unsigned int signature_len = 0;
	int ret = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH,signature, &signature_len, rsa_priv_key);

	//écrire l'identité dans le fichier de certification
	fwrite(identity_dup,1,strlen(identity_dup),certificate_file);
	
	//écrire la clé publique dans le fichier de certification
	ret = PEM_write_RSA_PUBKEY(certificate_file,pub_key_client);

	//mettre la signature dans le fichier de certification 
	fwrite(signature,1,signature_len,certificate_file);
	
	fclose(certificate_file);

}






int main(int argc, char* argv[]) {
  
printf ("***./prog name your_public_key_file_path *** \n");
  if(argc < 3)
	{
		printf("nombre d'arguments insuffisants\n");
		exit(-1);
	}
   
  char *identity = argv[1];
  char *pub_key_client = argv[2];	
  certificate_request(identity,pub_key_client);

  return 0;
}

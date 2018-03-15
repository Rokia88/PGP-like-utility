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

unsigned char* decrypt (unsigned char *encrypted, RSA *priv_key, long enc_message_length, long original_length)
{
	unsigned char *decrypted = (unsigned char *)malloc(original_length);
        int n = RSA_private_decrypt(enc_message_length, encrypted, decrypted, priv_key, RSA_PKCS1_PADDING);
	if(n == -1)
	{
		fputs("\n.Impossible de dechiffrer\n",stderr);
		exit(-1);
	}
	return decrypted;
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

void pgp_decrypt(char *file_to_decrypt_name,char *private_key_file_name,char *sym_key_file_name)
{

	//charger la clé privée RSA
	RSA *rsa_priv_key  = load_privkey(private_key_file_name);

	//récupération de la clé symétrique
	FILE *file;
	file = fopen(sym_key_file_name, "rb");
	if(file == NULL)
	{
		fputs("Echec du chargement de fichier!\n",stderr);
		exit(-1);
	}

	struct stat file_status;
	long enc_message_length = 0;
	unsigned char *file_buffer = NULL;
	stat(sym_key_file_name, &file_status);
	long file_size = file_status.st_size;
	file_buffer = (unsigned char *)malloc(file_size); 
	fread(file_buffer,1,file_size,file);
	fclose(file);
	unsigned char *key = decrypt(file_buffer, rsa_priv_key,file_size,SYM_KEY_SIZE);

	//lire le contenu du fichier et le mettre dans une chaine de caractère
	file = fopen(file_to_decrypt_name, "rb");
	if(file == NULL)
	{
		fputs("Echec du chargement de fichier!\n",stderr);
		exit(-1);
	}
	stat(file_to_decrypt_name, &file_status);
	file_size = file_status.st_size;
	file_buffer = (char *)malloc(file_size);
	fread(file_buffer,1,file_size,file);
	fclose(file);

	//déchiffrer le fichier avec la clé symétrique 
	AES_KEY aes;
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv,0,AES_BLOCK_SIZE);
  	unsigned int encrypted_len = (unsigned int)file_size;
  	unsigned int plain_text_len = (encrypted_len % AES_BLOCK_SIZE == 0) ? encrypted_len : (encrypted_len / AES_BLOCK_SIZE +1) * AES_BLOCK_SIZE;
  	char decrypted[plain_text_len];	
  	int ret = AES_set_decrypt_key(key,128,&aes);
  	AES_cbc_encrypt(file_buffer,decrypted,plain_text_len, &aes, iv, AES_DECRYPT);
	unsigned int length = strlen(decrypted);
	
	//mettre le contenu déchiffré dans le fichier file_to_decrypt_name_D.txt
	char *decrypted_file_name = strchr(file_to_decrypt_name,'.');
	if(decrypted_file_name!= NULL)
	{
		*decrypted_file_name = '\0';
	}
	strcat(file_to_decrypt_name,"_D.txt");
	file = fopen(file_to_decrypt_name, "wb");
	fwrite(decrypted,1,length,file);
	fclose(file);
	

}
int main(int argc, char* argv[]) {

	printf ("***./prog file_to_decrypt_path private_key_path sym_key_path*** \n");
  if(argc < 4)
	{
		printf("nombre d'arguments insuffisants\n");
		exit(-1);
	}
   
  char *name = argv[1];
  char *priv_key = argv[2];
  char *sym_key =argv[3];	
  pgp_decrypt(name,priv_key,sym_key);

  return 0;
}

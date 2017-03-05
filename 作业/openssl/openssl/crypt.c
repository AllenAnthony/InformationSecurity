#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")



char* MD5(char* file)
{
	int leng, cou;
	char* data;
	char* res;
	FILE* fp;
	MD5_CTX c;

	fp = fopen(file, "rb");

	data = (char*)malloc(1024); 

	res = (char*)malloc(16);

	MD5_Init(&c);
	while ((leng = fread(data, 1, 1024, fp)) > 0)
		MD5_Update(&c, data, leng);

	MD5_Final(res, &c);

	fclose(fp);
	free(data);

	return res;
}
char* RSASign(char* S, RSA* myRSA)
{
	char* sign;
	sign = (char *)malloc(RSA_size(myRSA));
	
	RSA_private_encrypt(16, S, sign, myRSA, RSA_PKCS1_PADDING);
	return sign;
}
int AppendSign(char* sign, RSA* myRSA,char* file, char* signfile)
{
	FILE* old_fp;
	FILE* new_fp;
	char* c;
	int i, file_size, sign_size;

	old_fp = fopen(file, "rb"); 

	new_fp = fopen(signfile, "wb");

	file_size = 0;
	while ((c = fgetc(old_fp)) != EOF)
	{
		fputc(c, new_fp);
		file_size++;
	}
	sign_size = RSA_size(myRSA);
	for (i = 0; i < sign_size; i++) 
		fputc(sign[i], new_fp);

	fwrite(&sign_size, sizeof(sign_size), 1, new_fp);
	fwrite(&file_size, sizeof(file_size), 1, new_fp); 

	fclose(old_fp);
	fclose(new_fp);
	return 0;
}
char* ExtractSign(char* signfile, char* checkfile, RSA* myRSA)
{
	FILE* sign_fp;
	FILE* file_fp;
	int i, file_size, sign_size;
	char* sign;

	sign_fp = fopen(signfile, "rb");  
	if (NULL == sign_fp)
	{
		printf("Can't open decrypt file in extracting!\n");
		return -1;
	}

	fseek(sign_fp, -(sizeof(sign_size)+sizeof(file_size)), SEEK_END);
	fread(&sign_size, sizeof(sign_size), 1, sign_fp);  
	fread(&file_size, sizeof(file_size), 1, sign_fp);  

	file_fp = fopen(checkfile, "wb");  
	if (NULL == file_fp)
	{
		fclose(sign_fp);
		return -1;
	}

	fseek(sign_fp, 0, SEEK_SET);
	for (i = 0; i < file_size; i++)  
		fputc(fgetc(sign_fp), file_fp);

	sign = (char *)malloc(sign_size); 
	if (NULL == sign)
	{
		fclose(sign_fp);
		fclose(file_fp);
		return -1;
	}

	for (i = 0; i < sign_size; i++) 
		sign[i] = fgetc(sign_fp);

	fclose(sign_fp);
	fclose(file_fp);
	return sign;
}
int RSACheck(char* sign, char* checkfile, RSA* myRSA)
{
	char* md5sign;
	char* md5check;
	int i;

	md5sign = (char *)malloc(16);
	if (NULL == md5sign)
		return NULL;

	RSA_public_decrypt(RSA_size(myRSA), sign, md5sign, myRSA, RSA_PKCS1_PADDING);
	md5check = MD5(checkfile); 

	for (i = 0; i < 16; i++)  
	if (md5sign[i] != md5check[i])
		return -1;
	return 0;
}

int main(void)
{        
    char* md5buf;        
    char* origin_sign;      
    char* check_sign;    
    RSA* myRSA;         
    char file[] = "sour.pdf";     
    char signfile[] = "signture";          
    char resultfile[] = "result.pdf"; 
	char encry[] = "encrypted";           
	char decry[] = "decrypted";         

	char myAESKEY[] = "the ASE private key is just here";
    printf("File to sign is %s.\n", file);

	md5buf = MD5(file);
    if (NULL == md5buf)
    {
        printf("MD5 hash fail!\n");
        return 0;
    }
    myRSA = RSA_generate_key(1024, RSA_3, NULL, NULL); 
    origin_sign = RSASign(md5buf, myRSA);
    if (NULL == origin_sign)
    {
        printf("Sign fail!\n");
        return 0;
    }
    free(md5buf);
	AppendSign(origin_sign, myRSA, file, signfile);

    free(origin_sign);

    printf("Sign success, Sign file is%s.\n", signfile);

	Encrypt(signfile, encry, myAESKEY);

	Decrypt(encry, decry, myAESKEY);

	check_sign = ExtractSign(decry, resultfile, myRSA);

    printf("Extract success, Extract file is named by %s.\n", resultfile);

	RSACheck(check_sign, resultfile, myRSA);

    free(check_sign);
    RSA_free(myRSA);


    return 0;
}

int Encrypt(char* signfile, char* aesfile, char* key)
{
	AES_KEY myKey;
	FILE* sign_fp;
	FILE* aes_fp;
	int filelen;
	char read_buf[16], write_buf[16];

	if (0 != AES_set_encrypt_key(key, strlen(key) * 8, &myKey))
	{
		printf("AES key must be 16, 24 or 32 bytes!\n");
		printf("Set encrypt key failed!\n");
		return -1;
	}

	sign_fp = fopen(signfile, "rb"); 
	if (NULL == sign_fp)
	{
		printf("Can't open sign file in encrypting!\n");
		return -1;
	}

	aes_fp = fopen(aesfile, "wb");
	if (NULL == aes_fp)
	{
		fclose(sign_fp);
		printf("Can't create encrypt file in encrypting!\n");
		return -1;
	}

	while (fread(read_buf, 1, 16, sign_fp) == 16)  
	{
		AES_encrypt(read_buf, write_buf, &myKey);
		fwrite(write_buf, 1, 16, aes_fp);
	}

	AES_encrypt(read_buf, write_buf, &myKey); 
	fwrite(write_buf, 1, 16, aes_fp);

	fseek(sign_fp, 0, SEEK_END);
	filelen = ftell(sign_fp);
	memcpy(read_buf, &filelen, sizeof(filelen));
	AES_encrypt(read_buf, write_buf, &myKey);
	fwrite(write_buf, 1, 16, aes_fp);

	fclose(sign_fp);
	fclose(aes_fp);
	return 0;
}
int Decrypt(char* aesfile, char* signfile, char* key)
{
	AES_KEY myKey;
	FILE* aes_fp;
	FILE* sign_fp;
	FILE* temp_fp;
	int i, filelen;
	char read_buf[16], write_buf[16];

	if (0 != AES_set_decrypt_key(key, strlen(key) * 8, &myKey))
	{
		printf("AES key must be 16, 24 or 32 bytes!\n");
		printf("Set decrypt key failed!\n");
		return -1;
	}

	aes_fp = fopen(aesfile, "rb"); 
	if (NULL == aes_fp)
	{
		printf("Can't open encrypt file in decrypting!\n");
		return -1;
	}

	temp_fp = fopen("temp", "wb"); 
	if (NULL == temp_fp)
	{
		fclose(aes_fp);
		printf("Can't create temp file in decrypting!\n");
		return -1;
	}

	while (fread(read_buf, 1, 16, aes_fp) == 16)  
	{
		AES_decrypt(read_buf, write_buf, &myKey);
		fwrite(write_buf, 1, 16, temp_fp);
	}
	fclose(aes_fp);
	fclose(temp_fp);

	temp_fp = fopen("temp", "rb"); 
	if (NULL == temp_fp)
	{
		printf("Can't open temp file in decrypting!\n");
		return -1;
	}
	fseek(temp_fp, -16, SEEK_END);
	fread(read_buf, 1, 16, temp_fp);
	filelen = *(int *)read_buf;

	sign_fp = fopen(signfile, "wb"); 
	if (NULL == sign_fp)
	{
		fclose(temp_fp);
		printf("Can't create decrypt file in decrypting!\n");
		return -1;
	}

	fseek(temp_fp, 0, SEEK_SET);
	for (i = 0; i < filelen; i++)  
		fputc(fgetc(temp_fp), sign_fp);

	fclose(temp_fp);
	fclose(sign_fp);
	remove("temp");  
	return 0;
}




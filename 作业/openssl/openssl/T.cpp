
#include <stdio.h>   // rsa_op.cpp
#include <string.h>
#include <openssl/evp.h>
//#include <crypto/evp/evp_locl.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
// 公钥指数
const unsigned char PUBLIC_EXPONENT_HEX[] =
{ 0x01, 0x00, 0x01 };

// 私钥指数
const unsigned char PRIVATE_EXPONENT_HEX[] =
{ 0x68, 0x4D, 0x32, 0xAA, 0xE1, 0x3B, 0x28, 0xEA, 0x96, 0x48, 0x9A, 0x52, 0xCF, 0xD4, 0x11, \
0xBE, 0x8E, 0xC1, 0xC2, 0x36, 0xF2, 0x95, 0xB3, 0x66, 0x2E, 0x54, 0x49, 0xFD, 0xAE, 0xDC, \
0x1D, 0x8E, 0x86, 0xAA, 0xAD, 0x60, 0x5E, 0x82, 0xCD, 0x99, 0xA9, 0x96, 0x64, 0xB0, 0x70, \
0xA0, 0xC5, 0x3A, 0x78, 0x8B, 0x5F, 0x85, 0x7A, 0x31, 0x21, 0x95, 0xDD, 0xDC, 0x99, 0x0E, \
0x88, 0x4E, 0xA1, 0x3D, 0x8B, 0xF8, 0x58, 0xA1, 0x7C, 0xE8, 0x8C, 0x37, 0xE1, 0x1D, 0x59, \
0x76, 0x81, 0x48, 0xFC, 0xF0, 0x1C, 0x37, 0x5A, 0x39, 0x23, 0x05, 0xAB, 0xC1, 0x75, 0xC8, \
0x7F, 0x7A, 0xA6, 0xB9, 0x25, 0x9D, 0x36, 0xE7, 0x9E, 0xC5, 0xCE, 0x32, 0x45, 0x34, 0xE2, \
0xEC, 0xDF, 0xB1, 0xD1, 0x4D, 0xC9, 0x31, 0x55, 0xBA, 0x14, 0xB1, 0xD1, 0x09, 0x22, 0x69, \
0xCF, 0x09, 0xB9, 0xF6, 0xB6, 0x68, 0xA1, 0x49 };
// 模数
const unsigned char MODULES_HEX[] =
{ 0xD7, 0x42, 0xCC, 0x97, 0x4D, 0x35, 0x1A, 0x8F, 0xB3, 0xAA, 0x42, 0xAA, 0x6D, 0x10, 0xEB, \
0x09, 0x58, 0xFA, 0xD2, 0xFB, 0x21, 0x0C, 0xDB, 0xBA, 0xB7, 0x22, 0x45, 0xE0, 0xF8, 0x1F, \
0x40, 0x26, 0xFD, 0x00, 0xAF, 0x83, 0x1B, 0x5C, 0xE5, 0x68, 0x7B, 0x3F, 0x81, 0x21, 0x9E, \
0xB4, 0x6B, 0x91, 0xCB, 0x5F, 0x2F, 0x6F, 0x18, 0xA6, 0x4B, 0xA0, 0x83, 0x33, 0x41, 0x7A, \
0x75, 0xE3, 0x4B, 0xF1, 0x23, 0xCC, 0xA5, 0x76, 0xD0, 0x58, 0x8F, 0x87, 0xE6, 0x4C, 0x66, \
0xB7, 0x83, 0x29, 0x16, 0xAE, 0x95, 0xE3, 0x76, 0x40, 0x0D, 0x54, 0xB8, 0x87, 0x0E, 0x8D, \
0x66, 0x0E, 0x0E, 0x1D, 0xC4, 0x16, 0xFD, 0x4F, 0xFA, 0xC4, 0xB9, 0x89, 0x5D, 0x01, 0x2D, \
0x86, 0x25, 0x44, 0x4B, 0x61, 0x31, 0xE2, 0xBD, 0x9A, 0xCD, 0x58, 0xE6, 0x6A, 0x94, 0xEC, \
0x94, 0x77, 0x64, 0x50, 0x8C, 0x04, 0xE8, 0x3F };

#define RSA_KEY_LENGTH 1024
static const char rnd_seed[] = "string to make the random number generator initialized";
class rsa_op
{
public:
	rsa_op();
	~rsa_op();

	// generate keys, usually no need to call it.
	int generate_key_str();

	// init params
	int set_params(const unsigned char *pub_expd = PUBLIC_EXPONENT_HEX, int pub_expd_len = 3,
		const unsigned char *pri_expd = PRIVATE_EXPONENT_HEX, int pri_expd_len = 128,
		const unsigned char *module = MODULES_HEX, int module_len = 128);

	// open keys
	int open_prikey_pubkey();
	int open_prikey();
	int open_pubkey();

	// private key to encryption and public key to decryption
	int prikey_encrypt(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len);
	int pubkey_decrypt(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len);
	// public key to encryption and private key to decryption
	int pubkey_encrypt(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len);
	int prikey_decrypt(const unsigned char *in, int in_len,
		unsigned char **out, int &out_len);

	int close_key();
protected:
	void free_res();

private:
	RSA *_pub_key;
	RSA *_pri_key;

	unsigned char *_pub_expd;
	unsigned char *_pri_expd;
	unsigned char *_module;

	int _pub_expd_len;
	int _pri_expd_len;
	int _module_len;
};





rsa_op::rsa_op()
{
	_pub_key = NULL;
	_pri_key = NULL;

	_pub_expd = NULL;
	_pri_expd = NULL;
	_module = NULL;
	_pub_expd_len = 0;
	_pri_expd_len = 0;
	_module_len = 0;
}

rsa_op::~rsa_op()
{
	close_key();
	free_res();
}

// 生成密钥函数
int rsa_op::generate_key_str()
{
	RSA *r = NULL;
	int bits = RSA_KEY_LENGTH;
	unsigned long e = RSA_F4;

	r = RSA_generate_key(bits, e, NULL, NULL);

	// 用作显示
	RSA_print_fp(stdout, r, 11);
	FILE *fp = fopen("f:\\new_keys", "w");
	if (NULL == fp)
	{
		return -1;
	}

	RSA_print_fp(fp, r, 0);
	fclose(fp);

	return 0;
}

// 初始化参数
int rsa_op::set_params(const unsigned char *pub_expd, int pub_expd_len,
	const unsigned char *pri_expd, int pri_expd_len,
	const unsigned char *module, int module_len)
{
	if (pub_expd)
	{

		_pub_expd_len = pub_expd_len;
		_pub_expd = new unsigned char[pub_expd_len];
		if (!_pub_expd)
		{
			free_res();
			return -1;
		}

		memcpy(_pub_expd, pub_expd, _pub_expd_len);
	}

	if (pri_expd)
	{
		_pri_expd_len = pri_expd_len;
		_pri_expd = new unsigned char[pri_expd_len];
		if (!_pri_expd)
		{
			free_res();
			return -1;
		}

		memcpy(_pri_expd, pri_expd, pri_expd_len);
	}

	if (module)
	{
		_module_len = module_len;
		_module = new unsigned char[module_len];
		if (!_module)
		{
			free_res();
			return -1;
		}

		memcpy(_module, module, module_len);
	}

	return 0;
}

// 在一个key中同时打开公钥和私钥，该key既可用作公钥函数，也可用作私钥函数
int rsa_op::open_prikey_pubkey()
{
	//构建RSA数据结构
	_pri_key = RSA_new();
	_pri_key->e = BN_bin2bn(_pub_expd, _pub_expd_len, _pri_key->e);
	_pri_key->d = BN_bin2bn(_pri_expd, _pri_expd_len, _pri_key->d);
	_pri_key->n = BN_bin2bn(_module, _module_len, _pri_key->n);

	RSA_print_fp(stdout, _pri_key, 0);

	return 0;
}

// 打开私钥
int rsa_op::open_prikey()
{
	//构建RSA数据结构
	_pri_key = RSA_new();
	//_pri_key->e = BN_bin2bn(_pub_expd, _pub_expd_len, _pri_key->e);
	_pri_key->d = BN_bin2bn(_pri_expd, _pri_expd_len, _pri_key->d);
	_pri_key->n = BN_bin2bn(_module, _module_len, _pri_key->n);

	return 0;
}
// 打开公钥
int rsa_op::open_pubkey()
{
	//构建RSA数据结构
	_pub_key = RSA_new();
	_pub_key->e = BN_bin2bn(_pub_expd, _pub_expd_len, _pub_key->e);
	//_pub_key->d = BN_bin2bn(_pri_expd, _pri_expd_len, _pub_key->d);
	_pub_key->n = BN_bin2bn(_module, _module_len, _pub_key->n);

	RSA_print_fp(stdout, _pub_key, 0);

	return 0;
}
// 私钥加密函数
int rsa_op::prikey_encrypt(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len)
{
	out_len = RSA_size(_pri_key);
	*out = (unsigned char *)malloc(out_len);
	if (NULL == *out)
	{

		printf("prikey_encrypt:malloc error!\n");
		return -1;
	}
	memset((void *)*out, 0, out_len);

	printf("prikey_encrypt:Begin RSA_private_encrypt ...\n");
	int ret = RSA_private_encrypt(in_len, in, *out, _pri_key, RSA_PKCS1_PADDING);
	//RSA_public_decrypt(flen, encData, decData, r,  RSA_NO_PADDING);

	return ret;
}
// 公钥解密函数，返回解密后的数据长度
int rsa_op::pubkey_decrypt(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len)
{
	out_len = RSA_size(_pub_key);
	*out = (unsigned char *)malloc(out_len);
	if (NULL == *out)
	{
		printf("pubkey_decrypt:malloc error!\n");
		return -1;
	}
	memset((void *)*out, 0, out_len);

	printf("pubkey_decrypt:Begin RSA_public_decrypt ...\n");
	int ret = RSA_public_decrypt(in_len, in, *out, _pub_key, RSA_PKCS1_PADDING);

	return ret;
}
// 公钥加密函数
int rsa_op::pubkey_encrypt(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len)
{
	out_len = RSA_size(_pub_key);
	*out = (unsigned char *)malloc(out_len);
	if (NULL == *out)
	{
		printf("pubkey_encrypt:malloc error!\n");
		return -1;
	}
	memset((void *)*out, 0, out_len);

	printf("pubkey_encrypt:Begin RSA_public_encrypt ...\n");
	int ret = RSA_public_encrypt(in_len, in, *out, _pub_key, RSA_PKCS1_PADDING/*RSA_NO_PADDING*/);


	return ret;
}

// 私钥解密函数，返回解密后的长度
int rsa_op::prikey_decrypt(const unsigned char *in, int in_len,
	unsigned char **out, int &out_len)
{
	out_len = RSA_size(_pri_key);
	*out = (unsigned char *)malloc(out_len);
	if (NULL == *out)
	{
		printf("prikey_decrypt:malloc error!\n");
		return -1;
	}
	memset((void *)*out, 0, out_len);

	printf("prikey_decrypt:Begin RSA_private_decrypt ...\n");
	int ret = RSA_private_decrypt(in_len, in, *out, _pri_key, RSA_PKCS1_PADDING);

	return ret;
}

// 释放分配的内存资源
void rsa_op::free_res()
{
	if (_pub_expd)
	{
		delete[]_pub_expd;
		_pub_expd = NULL;
	}

	if (_pri_expd)
	{
		delete[]_pri_expd;
		_pri_expd = NULL;
	}
	if (_module)
	{
		delete[]_module;
		_module = NULL;
	}
}

// 释放公钥和私钥结构资源
int rsa_op::close_key()
{
	if (_pub_key)
	{
		RSA_free(_pub_key);
		_pub_key = NULL;
	}

	if (_pri_key)
	{
		RSA_free(_pri_key);
		_pri_key = NULL;
	}

	return 0;
}




#ifdef WIN32
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#endif
int main(int argc, char **argv)
{
	char origin_text[] = "hello world!";

	// 由于采用RSA_PKCS1_PADDING方式，因此最大长度不要超过（即- 11）
	int origin_len = sizeof(origin_text);
	int enc_len = 0;
	int dec_len = 0;
	unsigned char *enc_data = NULL;
	unsigned char *dec_data = NULL;

	rsa_op ro;
	// 下面是重新生成key的代码，一般不需要
	// ro.generate_key_str();

	ro.set_params();
	ro.open_prikey_pubkey();
	ro.open_pubkey();

	// 下面两行是私钥加密，公钥解密
	ro.prikey_encrypt((const unsigned char *)origin_text, origin_len, (unsigned char **)&enc_data, enc_len);
	ro.pubkey_decrypt(enc_data, enc_len, (unsigned char **)&dec_data, dec_len);

	// 下面两行是公钥加密，私钥解密
	//ro.pubkey_encrypt((const unsigned char *)origin_text, origin_len, (unsigned char **)&enc_data, enc_len);
	//ro.prikey_decrypt(enc_data, enc_len, (unsigned char **)&dec_data, dec_len);

	delete[]enc_data;
	delete[]dec_data;

	return 0;
}
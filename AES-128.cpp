#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h> 
#include <map>
#include <string>
#include <vector>
#include <random>
#include <array>
#include <iomanip>
using namespace std;
constexpr size_t IV_SIZE = 12;

s32 tssecurity_encrypt_aes128_cbc(pu8 key, u32 keyLength, pu8 data, u32 dataLength, pu8 initVector, u32 initVectorLength, pu8 cipheredData, int cipheredDataLength);
s32 tssecurity_decrypt_aes128_cbc(pu8 key, u32 keyLength, pu8 cipheredData, u32 cipheredDataLength, pu8 initVector, u32 initVectorLength, pu8 plainData, int plainDataLength);
s32 tssecurity_generate_aes128_cmac(pu8 key, u32 keyLength, pu8 data, u32 dataLength, pu8 cmac, u32 cmacLength);
s32 tssecurity_encrypt_aes128_ecb(pu8 key, pu8 data, u32 dataLength, pu8 cipheredData, int *cipheredDataLength);
s32 tssecurity_decrypt_aes128_ecb(pu8 key, pu8 decipheredData, int* decipheredDataLength, pu8 data, u32 dataLength);
s32 tssecurity_encrypt_aes128_gcm_aad(pu8 key, pu8 iv, u32 ivLength, pu8 data, u32 dataLength, pu8 cipheredData, int* cipheredDataLength, pu8 tag, u32 tagLength, pu8 aad, u32 aadLength);
s32 tssecurity_encrypt_aes128_gcm(pu8 key, pu8 iv, u32 ivLength, pu8 data, u32 dataLength, pu8 cipheredData, int* cipheredDataLength, pu8 tag, u32 tagLength);
s32 tssecurity_decrypt_aes128_gcm_aad(pu8 key, pu8 iv, u32 ivLength, pu8 cipheredData, u32 cipheredDataLength, pu8 data, int* dataLength, pu8 tag, u32 tagLength, pu8 aad, u32 aadLength);
s32 tssecurity_decrypt_aes128_gcm(pu8 key, pu8 iv, u32 ivLength, pu8 cipheredData, u32 cipheredDataLength, pu8 data, int* dataLength, pu8 tag, u32 tagLength);

std::array<unsigned char, IV_SIZE> generate_random_iv();

/***************************************************************
 * @file       pkcs7_padding
 * @brief      PKCS7填充
 * @param      数据||块大小
 * @author     ？？？
 **************************************************************/
vector<unsigned char> pkcs7_padding(const vector<unsigned char>& data, int blockSize)
{
	int paddingSize = blockSize - (data.size() % blockSize);
	vector<unsigned char> paddedData(data);
	for (int i = 0; i < paddingSize; ++i) {
		paddedData.push_back(paddingSize);
	}
	return paddedData;
}

/***************************************************************
 * @file       tssecurity_encrypt_aes128_cbc
 * @brief      AES-128-CBC加密
 * @param      密钥||密钥长度||原始数据||原始数据长度||向量||向量长度||加密数据||加密数据长度
 * @author     ？？？
 **************************************************************/
s32 tssecurity_encrypt_aes128_cbc(pu8 key, u32 keyLength, pu8 data, u32 dataLength, pu8 initVector, u32 initVectorLength, pu8 cipheredData, int cipheredDataLength)
{
	EVP_CIPHER_CTX* cbc_ctx = EVP_CIPHER_CTX_new();
	vector<unsigned char> datatemp;
	vector<unsigned char> datapkcs;
	datatemp.assign(data, data + dataLength);
	datapkcs = pkcs7_padding(datatemp, 16);
	//vector 转 数组
	unsigned char* dataencrypt = new  unsigned char[datapkcs.size()];
	if (!datapkcs.empty())
	{
		memcpy(dataencrypt, &datapkcs[0], datapkcs.size() * sizeof(unsigned char));
	}
	int result1=EVP_EncryptInit_ex(cbc_ctx, EVP_aes_128_cbc(), NULL, key, initVector);
	int result2=EVP_CIPHER_CTX_set_padding(cbc_ctx, 0);
	int result3=EVP_EncryptUpdate(cbc_ctx, cipheredData,&cipheredDataLength, dataencrypt, datapkcs.size() * sizeof(unsigned char));
	if (result3 <= 0) {
		unsigned long errCode;
		char* err = NULL;
		errCode = ERR_get_error();
		if (errCode) {
			err = ERR_error_string(errCode, NULL);
			fprintf(stderr, "Encryption error: %s\n", err);
			log("%s", err);
			// 清理并返回错误  
		}
		else {
			fprintf(stderr, "Unknown encryption error\n");
			log("Unknown encryption error");
			// 清理并返回错误  
		}
	}
	int result4 =EVP_EncryptFinal_ex(cbc_ctx,cipheredData, &cipheredDataLength);
    EVP_CIPHER_CTX_free(cbc_ctx);
	if (result1 == 1 && result2==1 && result3==1 && result4==1) 
	{		
		return 0;
	}
	return 1;
}

/***************************************************************
 * @file       tssecurity_decrypt_aes128_cbc
 * @brief      AES-128-CBC解密
 * @param      密钥||密钥长度||加密数据||加密数据长度||向量||向量长度||解密数据||解密数据长度
 * @author     ？？？
 **************************************************************/
s32 tssecurity_decrypt_aes128_cbc(pu8 key, u32 keyLength, pu8 cipheredData, u32 cipheredDataLength, pu8 initVector, u32 initVectorLength, pu8 plainData, int plainDataLength)
{
	EVP_CIPHER_CTX* cbc_ctx = EVP_CIPHER_CTX_new();
	int result1=EVP_DecryptInit_ex(cbc_ctx, EVP_aes_128_cbc(), NULL, key, initVector);
	int result2=EVP_CIPHER_CTX_set_padding(cbc_ctx, 0);
	int result3 = EVP_DecryptUpdate(cbc_ctx, plainData, &plainDataLength, cipheredData, cipheredDataLength);
	if (result3 <= 0) {
		unsigned long errCode;
		char* err = NULL;
		errCode = ERR_get_error();
		if (errCode) {
			err = ERR_error_string(errCode, NULL);
			fprintf(stderr, "Decryption error: %s\n", err);
			log("%s",err);
			// 清理并返回错误  
		}
		else {
			fprintf(stderr, "Unknown decryption error\n");
			log("Unknown encryption error");
			// 清理并返回错误  
		}
	}
	int result4=EVP_DecryptFinal_ex(cbc_ctx, plainData, &plainDataLength);
	EVP_CIPHER_CTX_free(cbc_ctx);
	if (result1 == 1 && result2 == 1 && result3 == 1 && result4 == 1)
	{
		return 0;
	}
	return 1;
}

//typedef unsigned __int64 size_t;
/***************************************************************
 * @file       tssecurity_generate_aes128_cmac
 * @brief      AES-128-CMAC
 * @param      密钥||密钥长度||原始数据||原始数据长度||CAMC||CMAC长度
 * @author     ？？？
 **************************************************************/
s32 tssecurity_generate_aes128_cmac(pu8 key, u32 keyLength, pu8 data,u32 dataLength, pu8 cmac, u32 cmacLength)
{
	CMAC_CTX* cmac_ctx = CMAC_CTX_new();
	int result1=CMAC_Init(cmac_ctx, key, keyLength, EVP_aes_128_cbc(), NULL);
	int result2=CMAC_Update(cmac_ctx, data, dataLength);
	int result3=CMAC_Final(cmac_ctx, cmac, &cmacLength);
	CMAC_resume(cmac_ctx);
	if (result1 == 1 && result2 == 1 && result3 == 1)
	{		
		return 0;
	}
	return 1;
}

/***************************************************************
 * @file       tssecurity_encrypt_aes128_ecb
 * @brief      AES-128-ECB加密
 * @param      密钥||原始数据||原始数据长度||加密数据||加密数据长度
 * @author     wanxiangyu
 **************************************************************/
s32 tssecurity_encrypt_aes128_ecb(pu8 key, pu8 data, u32 dataLength, pu8 cipheredData, int* cipheredDataLength)
{
	EVP_CIPHER_CTX* ecb_ctx = EVP_CIPHER_CTX_new();
	if (EVP_EncryptInit_ex(ecb_ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
		EVP_CIPHER_CTX_free(ecb_ctx);
		return 0;
	}
	if (EVP_EncryptUpdate(ecb_ctx, cipheredData, cipheredDataLength, data, dataLength) != 1) {
		EVP_CIPHER_CTX_free(ecb_ctx);
		return 0;
	}
	if (EVP_EncryptFinal_ex(ecb_ctx, cipheredData, cipheredDataLength) != 1) {
		EVP_CIPHER_CTX_free(ecb_ctx);
		return 0;
	}

	EVP_CIPHER_CTX_free(ecb_ctx);
	return 1;
}

/***************************************************************
 * @file       tssecurity_decrypt_aes128_ecb
 * @brief      AES-128-ECB解密
 * @param      密钥||加密数据||加密数据长度||解密数据||解密数据长度 
 * @author     wanxiangyu
 **************************************************************/

s32 tssecurity_decrypt_aes128_ecb(pu8 key, pu8 decipheredData, int* decipheredDataLength, pu8 data, u32 dataLength)
{
	EVP_CIPHER_CTX* ecb_ctx = EVP_CIPHER_CTX_new();
	if (EVP_DecryptInit_ex(ecb_ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
		EVP_CIPHER_CTX_free(ecb_ctx);
		return 0;
	}
	if (EVP_DecryptUpdate(ecb_ctx, decipheredData, decipheredDataLength, data, dataLength) != 1) {
		EVP_CIPHER_CTX_free(ecb_ctx);
		return 0;
	}
	if (EVP_DecryptFinal_ex(ecb_ctx, decipheredData, decipheredDataLength) != 1) {
		EVP_CIPHER_CTX_free(ecb_ctx);
		return 0;
	}
	EVP_CIPHER_CTX_free(ecb_ctx);
	return 1;
}

/***************************************************************
 * @file       tssecurity_encrypt_aes128_gcm_aad
 * @brief      AES-128-GCM加密
 * @param      密钥||IV向量||IV向量长度||原始数据||原始数据长度||加密数据||加密数据长度||认证标签||认证标签长度||附加认证数据（可选）||附加认证数据长度（可选）
 * @author     wanxiangyu
 * @Sample usage:   
 * 1、 初始化AES-128-GCM加密上下文
 * 2、 设置IV和密钥
 * 3、 提供AAD数据（可选）
 * 4、 加密数据
 * 5、 获取并设置认证标签
 * 6、 释放上下文并返回结果
 **************************************************************/
s32 tssecurity_encrypt_aes128_gcm_aad(pu8 key, pu8 iv, u32 ivLength, pu8 data, u32 dataLength, pu8 cipheredData, int* cipheredDataLength, pu8 tag, u32 tagLength, pu8 aad, u32 aadLength)
{
	EVP_CIPHER_CTX* gcm_ctx = EVP_CIPHER_CTX_new();
	int len = 0;
	if (EVP_EncryptInit_ex(gcm_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_EncryptInit_ex(gcm_ctx, NULL, NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}
	if (aad && aadLength > 0) {
		if (EVP_EncryptUpdate(gcm_ctx, NULL, &len, aad, aadLength) != 1) {
			EVP_CIPHER_CTX_free(gcm_ctx);
			return 0;
		}
	}

	if (EVP_EncryptUpdate(gcm_ctx, cipheredData, &len, data, dataLength) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}
	*cipheredDataLength = len;

	if (EVP_EncryptFinal_ex(gcm_ctx, cipheredData + len, &len) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}
	*cipheredDataLength += len;

	if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_GET_TAG, tagLength, tag) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	EVP_CIPHER_CTX_free(gcm_ctx);
	return 1;
}

/***************************************************************
 * @file       tssecurity_encrypt_aes128_gcm(不加AAD)
 * @brief      AES-128-GCM加密
 * @param      密钥||IV向量||IV向量长度||原始数据||原始数据长度||加密数据||加密数据长度||认证标签||认证标签长度
 * @author     wanxiangyu
 **************************************************************/
s32 tssecurity_encrypt_aes128_gcm(pu8 key, pu8 iv, u32 ivLength, pu8 data, u32 dataLength, pu8 cipheredData, int* cipheredDataLength, pu8 tag, u32 tagLength)
{
	EVP_CIPHER_CTX* gcm_ctx = EVP_CIPHER_CTX_new();
	int len = 0;

	if (EVP_EncryptInit_ex(gcm_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_EncryptInit_ex(gcm_ctx, NULL, NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_EncryptUpdate(gcm_ctx, cipheredData, &len, data, dataLength) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}
	*cipheredDataLength = len;

	if (EVP_EncryptFinal_ex(gcm_ctx, cipheredData + len, &len) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}
	*cipheredDataLength += len;

	if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_GET_TAG, tagLength, tag) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	EVP_CIPHER_CTX_free(gcm_ctx);
	return 1;
}

/***************************************************************
 * @file       tssecurity_decrypt_aes128_gcm_aad
 * @brief      AES-128-GCM加密
 * @param      密钥||IV向量||IV向量长度||加密数据||加密数据长度||解密数据||解密数据长度||认证标签||认证标签长度||附加认证数据（可选）||附加认证数据长度（可选）
 * @author     wanxiangyu
 **************************************************************/
s32 tssecurity_decrypt_aes128_gcm_aad(pu8 key, pu8 iv, u32 ivLength, pu8 cipheredData, u32 cipheredDataLength, pu8 data, int* dataLength, pu8 tag, u32 tagLength, pu8 aad, u32 aadLength)
{
	EVP_CIPHER_CTX* gcm_ctx = EVP_CIPHER_CTX_new();
	int len = 0;
	int result = 0;

	if (EVP_DecryptInit_ex(gcm_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_DecryptInit_ex(gcm_ctx, NULL, NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (aad && aadLength > 0) {
		if (EVP_DecryptUpdate(gcm_ctx, NULL, &len, aad, aadLength) != 1) {
			EVP_CIPHER_CTX_free(gcm_ctx);
			return 0;
		}
	}

	if (EVP_DecryptUpdate(gcm_ctx, data, &len, cipheredData, cipheredDataLength) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}
	*dataLength = len;

	if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_TAG, tagLength, tag) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	result = EVP_DecryptFinal_ex(gcm_ctx, data + len, &len);
	EVP_CIPHER_CTX_free(gcm_ctx);

	if (result != 1) {
		return 0;
	}

	*dataLength += len;
	return 1;
}

/***************************************************************
 * @file       tssecurity_decrypt_aes128_gcm(不加AAD)
 * @brief      AES-128-GCM解密
 * @param      密钥||IV向量||IV向量长度||加密数据||加密数据长度||解密数据||解密数据长度||认证标签||认证标签长度
 * @author     wanxiangyu
 **************************************************************/
s32 tssecurity_decrypt_aes128_gcm(pu8 key, pu8 iv, u32 ivLength, pu8 cipheredData, u32 cipheredDataLength, pu8 data, int* dataLength, pu8 tag, u32 tagLength)
{
	EVP_CIPHER_CTX* gcm_ctx = EVP_CIPHER_CTX_new();
	int len = 0;
	int result = 0;

	if (EVP_DecryptInit_ex(gcm_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_DecryptInit_ex(gcm_ctx, NULL, NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	if (EVP_DecryptUpdate(gcm_ctx, data, &len, cipheredData, cipheredDataLength) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}
	*dataLength = len;

	if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_TAG, tagLength, tag) != 1) {
		EVP_CIPHER_CTX_free(gcm_ctx);
		return 0;
	}

	result = EVP_DecryptFinal_ex(gcm_ctx, data + len, &len);
	EVP_CIPHER_CTX_free(gcm_ctx);

	if (result != 1) {
		return 0;
	}

	*dataLength += len;
	return 1;
}

/***************************************************************
 * @file       generate_random_iv
 * @brief      随机生成12BYTE的IV向量
 * @param      NULL
 * @return	   array<unsigned char, 12>
 * @author     wanxiangyu
 **************************************************************/
std::array<unsigned char, IV_SIZE> generate_random_iv() {
	std::array<unsigned char, IV_SIZE> iv;
	std::random_device rd;
	std::mt19937 generator(rd());
	// 0x00-0xFF
	std::uniform_int_distribution<int> distribution(0, 255);

	for (auto& byte : iv) {
		byte = static_cast<unsigned char>(distribution(generator));
	}

	return iv;
}



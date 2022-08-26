摘要，加/解密， 签名/验证


摘要：
disgest_evp.c : 关于摘要算法的evp高级接口实现代码
md5_and_sha_example.c ：关于MD5和sha摘要算法的低级接口的实现代码

加密：
symmetric_encrypt_evp.c：关于对称加密算法的evp高级接口实现。
asymmetry_encrypt_evp.c：关于非对称加密算法rsa的evp高级接口实现
asymmetry_rsa.c ：关于非对称加密算法rsa的低级接口实现

数字签名：
rsa_sign_evp.c：关于非对称加密算法rsa的evp高级接口数字签名实现


参考：
https://github.com/openssl/openssl/blob/master/doc/man3/
https://www.openssl.org/docs/man1.1.1/man3/
https://wiki.openssl.org/index.php/Main_Page


密码算法： EVP_CIPHER
摘要算法： EVP_MD

生成私钥：openssl genrsa -out pri-key_2048_rsa.pem 2048 
生成公钥：openssl rsa -pubout -in pri-key_2048_rsa.pem -out pub-key_2048_rsa.pem
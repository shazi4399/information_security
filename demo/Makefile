obj=disgest_evp disgest_low envelope1 envelope \
read_x509 rsa_encry_evp rsa_encry_low \
rsa_sign_evp symmetric_encrypt_evp


all: $(obj)
FLAGE=-Wall

STATIC_FLAG=-static -lcrypto 

disgest_evp: disgest_evp.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

disgest_low: disgest_low.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

envelope1: envelope1.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

envelope: envelope.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

read_x509: read_x509.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

rsa_encry_evp: rsa_encry_evp.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

rsa_encry_low: rsa_encry_low.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

rsa_sign_evp: rsa_sign_evp.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

symmetric_encrypt_evp: symmetric_encrypt_evp.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@


clean:
	-rm $(obj)

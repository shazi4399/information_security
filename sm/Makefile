obj= sm3_file sm3_str sm4_file sm4_str sm2_enc \
sm2_ds_str sm2_ds_file key_derive sm4_file1 envelope

FLAGE=-Wall

all: $(obj)

envelope: envelope.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

key_derive: key_derive.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

sm2_ds_file: sm2_ds_file.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

sm2_ds_str: sm2_ds_str.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

sm2_enc: sm2_enc.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

sm4_str: sm4_str.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

sm4_file1: sm4_file1.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

sm4_file: sm4_file.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

sm3_file: sm3_file.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

sm3_str: sm3_str.c
	gcc -g $(FLAGE) $^ -lcrypto -std=c11 -o $@

clean:
	-rm $(obj)

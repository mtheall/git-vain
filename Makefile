git-vain: git-vain.c
	$(CC) $< -o $@ #-O3 -g -lcrypto -pthread -lm -Wall -DUSE_OPENSSL -DNO_STRLCPY

install: git-vain
	cp git-vain /usr/local/bin

clean:
	rm -f git-vain


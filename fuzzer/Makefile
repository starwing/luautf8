ALL: lua-utf8.so fuzz-valid fuzz-clean fuzz-invalid fuzz-normalize

lua-utf8.so: ../lutf8lib.c
	gcc -g -fPIC $$(pkg-config --cflags lua5.1) ../lutf8lib.c -shared -o lua-utf8.so

fuzz-valid: fuzz-valid.c
	clang -g -fsanitize=address,fuzzer,undefined -I/usr/include/lua5.1 -llua5.1 fuzz-valid.c -o fuzz-valid

fuzz-clean: fuzz-clean.c
	clang -g -fsanitize=address,fuzzer,undefined -I/usr/include/lua5.1 -llua5.1 fuzz-clean.c -o fuzz-clean

fuzz-invalid: fuzz-invalid.c
	clang -g -fsanitize=address,fuzzer,undefined -I/usr/include/lua5.1 -llua5.1 fuzz-invalid.c -o fuzz-invalid

fuzz-normalize: fuzz-normalize.c
	clang -g -fsanitize=address,fuzzer,undefined -I/usr/include/lua5.1 -llua5.1 -licuuc fuzz-normalize.c -o fuzz-normalize

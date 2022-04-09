.phony: all clean compile run

all: clean compile run

compile:
	javac -h ../jni_library cn/edu/zjucst/jni/ZKVotingJNI.java

run:
	cp ../../build/src/libzkvoting.so .
	java -Djava.library.path=. cn/edu/zjucst/jni/ZKVotingJNI

clean:
	-rm cn/edu/zjucst/jni/*.class
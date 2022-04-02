all: clean compile run

compile:
	javac -h .. cn/edu/zjucst/jni/ZKVotingJNI.java

clean:
	rm cn/edu/zjucst/jni/*.class

run:
	cp ../../build/src/libzkvotingd.so ./libzkvoting.so && java -Djava.library.path=. cn.edu.zjucst.jni.ZKVotingJNI

.phony: clean compile

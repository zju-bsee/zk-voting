../cn_edu_zjucst_jni_ZKVotingJNI.h: cn/edu/zjucst/jni/ZKVotingJNI.java
	javac -h .. cn/edu/zjucst/jni/ZKVotingJNI.java
clean:
	rm cn/edu/zjucst/jni/*.class
run:
	cp ../../build/src/libzkvoting.so . && java -Djava.library.path=. cn.edu.zjucst.jni.ZKVotingJNI

.phony: clean
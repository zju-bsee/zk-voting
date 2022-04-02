# 依赖安装
```sh
sudo apt-get install build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev
```

# 拉取模块
```sh
cd zk-voting
git submodule update --init --recursive --depth 1
```

# 构建
```sh
mkdir build && cd build && cmake ..
make
```

# 运行测试
测试程序需要传入一个证明者的秘密输入x，程序打印其证明x^3 + x + 5 = 35的结果
```sh
./build/src/test 3
```

# 测试JNI
测试前需要保证动态链接库构建完成:
```sh
cd build
make
```
之后在JNI文件夹下编译Java字节码文件、拷贝构建的动态链接库并运行:
```sh
cd src/jni
make
```
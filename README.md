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
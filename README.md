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
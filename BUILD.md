# Building ppceeder

## Install Dependencies

```bash
sudo apt install git \
                 cmake \
                 ninja-build \
                 build-essential
                 pkg-config \
                 libssl-dev
```

## Get Code

```bash
git clone https://github.com/belovachap/ppceeder.git
cd ppceeder 
```

## Build

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build . -j$(nproc)
```


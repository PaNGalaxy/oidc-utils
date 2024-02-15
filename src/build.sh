rm -rf build
mkdir build
cd build
cmake ..
make
cpack -G $1
javac -h . FalconDemo1.java 
clang++-16 -shared -std=c++20 -Wall -O3 -march=native -mtune=native -I include/ -I /usr/lib/jvm/java-17-openjdk-amd64/include -I /usr/lib/jvm/java-17-openjdk-amd64/include/linux -I sha3/include Falcon1.cpp -o libfalcon1.so -lstdc++ -fPIC -lgmpxx -lgmp
sudo cp /home/unixusername/falcon/libfalcon1.so /usr/lib/x86_64-linux-gnu/jni
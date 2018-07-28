FROM ubuntu:xenial

RUN apt-get update
RUN apt-get install -y git wget cmake gcc build-essential
# some deps via: https://github.com/richinseattle/Dockerfiles/blob/master/afl-dyninst.Dockerfile
RUN apt-get install -y libelf-dev libelf1 libiberty-dev libboost-all-dev libgtest-dev libgflags-dev
RUN mkdir /code

# build, install dyninst
RUN wget -O /code/dyninst.tar.gz https://github.com/dyninst/dyninst/archive/v9.3.2.tar.gz
RUN cd /code && \
    tar xf /code/dyninst.tar.gz && \
    mv dyninst-9.3.2 dyninst
RUN cd /code/dyninst && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make -j8 && \
    make install && \
    ldconfig

# build gtest
RUN cd /usr/src/gtest && \
    cmake ./CMakeLists.txt && \
    make && \
    cp *.a /usr/lib

# build functionsimsearch
RUN cd /code && \
    git clone https://github.com/steven-hh-ding/functionsimsearch && \
    cd functionsimsearch && \
    mv third_party third_party_temp && \
    mkdir third_party && \
    cd third_party && \
    git clone https://github.com/okdshin/PicoSHA2.git && \
    git clone https://github.com/trailofbits/pe-parse.git && \
    git clone https://github.com/PetterS/spii.git && \
    cp -R ../third_party_temp/* ./ && \
    cd pe-parse && \
    cmake -D CMAKE_CXX_FLAGS=-Wstrict-overflow=1 . && \
    sed -i -e 's/overflow\=5/overflow\=1/g' ./cmake/compilation_flags.cmake && \
    cat ./cmake/compilation_flags.cmake && \
    make -j 16 && \
    cd ../spii && \
    cmake . -DBUILD_SHARED_LIBS=true && \
    make -j 16 && \
    make install && \
    cp /usr/local/lib/libspii* /usr/lib && \
    cd ../.. && \
    sed -i -e 's/isnan/std::isnan/g' ./third_party/spii/include/spii/large_auto_diff_term.h && \
    make -j 16

# dispatch via entrypoint script
# recommend mapping the /pwd volume, probably like (for ELF file):
#
#    docker run -it --rm -v $(pwd):/pwd functionsimsearch disassemble ELF /pwd/someexe
VOLUME /pwd
WORKDIR /code/functionsimsearch
RUN chmod +x /code/functionsimsearch/entrypoint.sh
ENTRYPOINT ["/code/functionsimsearch/entrypoint.sh"]
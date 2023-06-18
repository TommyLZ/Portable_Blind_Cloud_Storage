cmake_minimum_required(VERSION 3.0)

project(MYSCHEME)

include_directories(Header)

add_executable(build main.cpp Source/Client.cpp  Source/PublicParam.cpp Source/Registration.cpp Source/KeyServer.cpp Source/CloudServer.cpp Source/KeyGen.cpp Source/KeyRetrieve.cpp)

link_directories(/usr/local/lib /lib/x86_64-linux-gnu/ /usr/include)
target_link_libraries(build pbc gmp cryptopp)

set(CMAKE_BUILD_TYPE Debug)
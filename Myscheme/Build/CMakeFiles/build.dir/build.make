# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/tommylz/文档/C++/Myscheme

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/tommylz/文档/C++/Myscheme/Build

# Include any dependencies generated for this target.
include CMakeFiles/build.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/build.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/build.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/build.dir/flags.make

CMakeFiles/build.dir/main.cpp.o: CMakeFiles/build.dir/flags.make
CMakeFiles/build.dir/main.cpp.o: ../main.cpp
CMakeFiles/build.dir/main.cpp.o: CMakeFiles/build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/build.dir/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/build.dir/main.cpp.o -MF CMakeFiles/build.dir/main.cpp.o.d -o CMakeFiles/build.dir/main.cpp.o -c /home/tommylz/文档/C++/Myscheme/main.cpp

CMakeFiles/build.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/build.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tommylz/文档/C++/Myscheme/main.cpp > CMakeFiles/build.dir/main.cpp.i

CMakeFiles/build.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/build.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tommylz/文档/C++/Myscheme/main.cpp -o CMakeFiles/build.dir/main.cpp.s

CMakeFiles/build.dir/Source/Client.cpp.o: CMakeFiles/build.dir/flags.make
CMakeFiles/build.dir/Source/Client.cpp.o: ../Source/Client.cpp
CMakeFiles/build.dir/Source/Client.cpp.o: CMakeFiles/build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/build.dir/Source/Client.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/build.dir/Source/Client.cpp.o -MF CMakeFiles/build.dir/Source/Client.cpp.o.d -o CMakeFiles/build.dir/Source/Client.cpp.o -c /home/tommylz/文档/C++/Myscheme/Source/Client.cpp

CMakeFiles/build.dir/Source/Client.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/build.dir/Source/Client.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tommylz/文档/C++/Myscheme/Source/Client.cpp > CMakeFiles/build.dir/Source/Client.cpp.i

CMakeFiles/build.dir/Source/Client.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/build.dir/Source/Client.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tommylz/文档/C++/Myscheme/Source/Client.cpp -o CMakeFiles/build.dir/Source/Client.cpp.s

CMakeFiles/build.dir/Source/PublicParam.cpp.o: CMakeFiles/build.dir/flags.make
CMakeFiles/build.dir/Source/PublicParam.cpp.o: ../Source/PublicParam.cpp
CMakeFiles/build.dir/Source/PublicParam.cpp.o: CMakeFiles/build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/build.dir/Source/PublicParam.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/build.dir/Source/PublicParam.cpp.o -MF CMakeFiles/build.dir/Source/PublicParam.cpp.o.d -o CMakeFiles/build.dir/Source/PublicParam.cpp.o -c /home/tommylz/文档/C++/Myscheme/Source/PublicParam.cpp

CMakeFiles/build.dir/Source/PublicParam.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/build.dir/Source/PublicParam.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tommylz/文档/C++/Myscheme/Source/PublicParam.cpp > CMakeFiles/build.dir/Source/PublicParam.cpp.i

CMakeFiles/build.dir/Source/PublicParam.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/build.dir/Source/PublicParam.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tommylz/文档/C++/Myscheme/Source/PublicParam.cpp -o CMakeFiles/build.dir/Source/PublicParam.cpp.s

CMakeFiles/build.dir/Source/Registration.cpp.o: CMakeFiles/build.dir/flags.make
CMakeFiles/build.dir/Source/Registration.cpp.o: ../Source/Registration.cpp
CMakeFiles/build.dir/Source/Registration.cpp.o: CMakeFiles/build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/build.dir/Source/Registration.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/build.dir/Source/Registration.cpp.o -MF CMakeFiles/build.dir/Source/Registration.cpp.o.d -o CMakeFiles/build.dir/Source/Registration.cpp.o -c /home/tommylz/文档/C++/Myscheme/Source/Registration.cpp

CMakeFiles/build.dir/Source/Registration.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/build.dir/Source/Registration.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tommylz/文档/C++/Myscheme/Source/Registration.cpp > CMakeFiles/build.dir/Source/Registration.cpp.i

CMakeFiles/build.dir/Source/Registration.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/build.dir/Source/Registration.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tommylz/文档/C++/Myscheme/Source/Registration.cpp -o CMakeFiles/build.dir/Source/Registration.cpp.s

CMakeFiles/build.dir/Source/KeyServer.cpp.o: CMakeFiles/build.dir/flags.make
CMakeFiles/build.dir/Source/KeyServer.cpp.o: ../Source/KeyServer.cpp
CMakeFiles/build.dir/Source/KeyServer.cpp.o: CMakeFiles/build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/build.dir/Source/KeyServer.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/build.dir/Source/KeyServer.cpp.o -MF CMakeFiles/build.dir/Source/KeyServer.cpp.o.d -o CMakeFiles/build.dir/Source/KeyServer.cpp.o -c /home/tommylz/文档/C++/Myscheme/Source/KeyServer.cpp

CMakeFiles/build.dir/Source/KeyServer.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/build.dir/Source/KeyServer.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tommylz/文档/C++/Myscheme/Source/KeyServer.cpp > CMakeFiles/build.dir/Source/KeyServer.cpp.i

CMakeFiles/build.dir/Source/KeyServer.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/build.dir/Source/KeyServer.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tommylz/文档/C++/Myscheme/Source/KeyServer.cpp -o CMakeFiles/build.dir/Source/KeyServer.cpp.s

CMakeFiles/build.dir/Source/CloudServer.cpp.o: CMakeFiles/build.dir/flags.make
CMakeFiles/build.dir/Source/CloudServer.cpp.o: ../Source/CloudServer.cpp
CMakeFiles/build.dir/Source/CloudServer.cpp.o: CMakeFiles/build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/build.dir/Source/CloudServer.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/build.dir/Source/CloudServer.cpp.o -MF CMakeFiles/build.dir/Source/CloudServer.cpp.o.d -o CMakeFiles/build.dir/Source/CloudServer.cpp.o -c /home/tommylz/文档/C++/Myscheme/Source/CloudServer.cpp

CMakeFiles/build.dir/Source/CloudServer.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/build.dir/Source/CloudServer.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tommylz/文档/C++/Myscheme/Source/CloudServer.cpp > CMakeFiles/build.dir/Source/CloudServer.cpp.i

CMakeFiles/build.dir/Source/CloudServer.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/build.dir/Source/CloudServer.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tommylz/文档/C++/Myscheme/Source/CloudServer.cpp -o CMakeFiles/build.dir/Source/CloudServer.cpp.s

CMakeFiles/build.dir/Source/KeyGen.cpp.o: CMakeFiles/build.dir/flags.make
CMakeFiles/build.dir/Source/KeyGen.cpp.o: ../Source/KeyGen.cpp
CMakeFiles/build.dir/Source/KeyGen.cpp.o: CMakeFiles/build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/build.dir/Source/KeyGen.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/build.dir/Source/KeyGen.cpp.o -MF CMakeFiles/build.dir/Source/KeyGen.cpp.o.d -o CMakeFiles/build.dir/Source/KeyGen.cpp.o -c /home/tommylz/文档/C++/Myscheme/Source/KeyGen.cpp

CMakeFiles/build.dir/Source/KeyGen.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/build.dir/Source/KeyGen.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tommylz/文档/C++/Myscheme/Source/KeyGen.cpp > CMakeFiles/build.dir/Source/KeyGen.cpp.i

CMakeFiles/build.dir/Source/KeyGen.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/build.dir/Source/KeyGen.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tommylz/文档/C++/Myscheme/Source/KeyGen.cpp -o CMakeFiles/build.dir/Source/KeyGen.cpp.s

CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o: CMakeFiles/build.dir/flags.make
CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o: ../Source/KeyRetrieve.cpp
CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o: CMakeFiles/build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o -MF CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o.d -o CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o -c /home/tommylz/文档/C++/Myscheme/Source/KeyRetrieve.cpp

CMakeFiles/build.dir/Source/KeyRetrieve.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/build.dir/Source/KeyRetrieve.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tommylz/文档/C++/Myscheme/Source/KeyRetrieve.cpp > CMakeFiles/build.dir/Source/KeyRetrieve.cpp.i

CMakeFiles/build.dir/Source/KeyRetrieve.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/build.dir/Source/KeyRetrieve.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tommylz/文档/C++/Myscheme/Source/KeyRetrieve.cpp -o CMakeFiles/build.dir/Source/KeyRetrieve.cpp.s

# Object files for target build
build_OBJECTS = \
"CMakeFiles/build.dir/main.cpp.o" \
"CMakeFiles/build.dir/Source/Client.cpp.o" \
"CMakeFiles/build.dir/Source/PublicParam.cpp.o" \
"CMakeFiles/build.dir/Source/Registration.cpp.o" \
"CMakeFiles/build.dir/Source/KeyServer.cpp.o" \
"CMakeFiles/build.dir/Source/CloudServer.cpp.o" \
"CMakeFiles/build.dir/Source/KeyGen.cpp.o" \
"CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o"

# External object files for target build
build_EXTERNAL_OBJECTS =

build: CMakeFiles/build.dir/main.cpp.o
build: CMakeFiles/build.dir/Source/Client.cpp.o
build: CMakeFiles/build.dir/Source/PublicParam.cpp.o
build: CMakeFiles/build.dir/Source/Registration.cpp.o
build: CMakeFiles/build.dir/Source/KeyServer.cpp.o
build: CMakeFiles/build.dir/Source/CloudServer.cpp.o
build: CMakeFiles/build.dir/Source/KeyGen.cpp.o
build: CMakeFiles/build.dir/Source/KeyRetrieve.cpp.o
build: CMakeFiles/build.dir/build.make
build: CMakeFiles/build.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/tommylz/文档/C++/Myscheme/Build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX executable build"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/build.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/build.dir/build: build
.PHONY : CMakeFiles/build.dir/build

CMakeFiles/build.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/build.dir/cmake_clean.cmake
.PHONY : CMakeFiles/build.dir/clean

CMakeFiles/build.dir/depend:
	cd /home/tommylz/文档/C++/Myscheme/Build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tommylz/文档/C++/Myscheme /home/tommylz/文档/C++/Myscheme /home/tommylz/文档/C++/Myscheme/Build /home/tommylz/文档/C++/Myscheme/Build /home/tommylz/文档/C++/Myscheme/Build/CMakeFiles/build.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/build.dir/depend

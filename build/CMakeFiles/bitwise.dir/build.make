# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.23

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
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/smhan/searchableHE_trials

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/smhan/searchableHE_trials/build

# Include any dependencies generated for this target.
include CMakeFiles/bitwise.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/bitwise.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/bitwise.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/bitwise.dir/flags.make

CMakeFiles/bitwise.dir/src/bitwise.cpp.o: CMakeFiles/bitwise.dir/flags.make
CMakeFiles/bitwise.dir/src/bitwise.cpp.o: ../src/bitwise.cpp
CMakeFiles/bitwise.dir/src/bitwise.cpp.o: CMakeFiles/bitwise.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/smhan/searchableHE_trials/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/bitwise.dir/src/bitwise.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/bitwise.dir/src/bitwise.cpp.o -MF CMakeFiles/bitwise.dir/src/bitwise.cpp.o.d -o CMakeFiles/bitwise.dir/src/bitwise.cpp.o -c /home/smhan/searchableHE_trials/src/bitwise.cpp

CMakeFiles/bitwise.dir/src/bitwise.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bitwise.dir/src/bitwise.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/smhan/searchableHE_trials/src/bitwise.cpp > CMakeFiles/bitwise.dir/src/bitwise.cpp.i

CMakeFiles/bitwise.dir/src/bitwise.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bitwise.dir/src/bitwise.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/smhan/searchableHE_trials/src/bitwise.cpp -o CMakeFiles/bitwise.dir/src/bitwise.cpp.s

CMakeFiles/bitwise.dir/src/binary.cpp.o: CMakeFiles/bitwise.dir/flags.make
CMakeFiles/bitwise.dir/src/binary.cpp.o: ../src/binary.cpp
CMakeFiles/bitwise.dir/src/binary.cpp.o: CMakeFiles/bitwise.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/smhan/searchableHE_trials/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/bitwise.dir/src/binary.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/bitwise.dir/src/binary.cpp.o -MF CMakeFiles/bitwise.dir/src/binary.cpp.o.d -o CMakeFiles/bitwise.dir/src/binary.cpp.o -c /home/smhan/searchableHE_trials/src/binary.cpp

CMakeFiles/bitwise.dir/src/binary.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bitwise.dir/src/binary.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/smhan/searchableHE_trials/src/binary.cpp > CMakeFiles/bitwise.dir/src/binary.cpp.i

CMakeFiles/bitwise.dir/src/binary.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bitwise.dir/src/binary.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/smhan/searchableHE_trials/src/binary.cpp -o CMakeFiles/bitwise.dir/src/binary.cpp.s

# Object files for target bitwise
bitwise_OBJECTS = \
"CMakeFiles/bitwise.dir/src/bitwise.cpp.o" \
"CMakeFiles/bitwise.dir/src/binary.cpp.o"

# External object files for target bitwise
bitwise_EXTERNAL_OBJECTS =

bin/bitwise: CMakeFiles/bitwise.dir/src/bitwise.cpp.o
bin/bitwise: CMakeFiles/bitwise.dir/src/binary.cpp.o
bin/bitwise: CMakeFiles/bitwise.dir/build.make
bin/bitwise: /home/smhan/helib_install_t/helib_pack/lib/libhelib.a
bin/bitwise: /home/smhan/helib_install_t/helib_pack/lib/libntl.so
bin/bitwise: /home/smhan/helib_install_t/helib_pack/lib/libgmp.so
bin/bitwise: CMakeFiles/bitwise.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/smhan/searchableHE_trials/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable bin/bitwise"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bitwise.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/bitwise.dir/build: bin/bitwise
.PHONY : CMakeFiles/bitwise.dir/build

CMakeFiles/bitwise.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bitwise.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bitwise.dir/clean

CMakeFiles/bitwise.dir/depend:
	cd /home/smhan/searchableHE_trials/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/smhan/searchableHE_trials /home/smhan/searchableHE_trials /home/smhan/searchableHE_trials/build /home/smhan/searchableHE_trials/build /home/smhan/searchableHE_trials/build/CMakeFiles/bitwise.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bitwise.dir/depend

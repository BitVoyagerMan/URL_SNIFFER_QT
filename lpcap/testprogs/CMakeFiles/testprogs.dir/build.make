﻿# CMAKE generated file: DO NOT EDIT!
# Generated by "NMake Makefiles" Generator, CMake Version 3.25

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

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

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE
NULL=nul
!ENDIF
SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "C:\Program Files\CMake\bin\cmake.exe"

# The command to remove a file.
RM = "C:\Program Files\CMake\bin\cmake.exe" -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\Red\Documents\sniffer\lpcap

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\Red\Documents\sniffer\lpcap

# Utility rule file for testprogs.

# Include any custom commands dependencies for this target.
include testprogs\CMakeFiles\testprogs.dir\compiler_depend.make

# Include the progress variables for this target.
include testprogs\CMakeFiles\testprogs.dir\progress.make

testprogs: testprogs\CMakeFiles\testprogs.dir\build.make
.PHONY : testprogs

# Rule to build all files generated by this target.
testprogs\CMakeFiles\testprogs.dir\build: testprogs
.PHONY : testprogs\CMakeFiles\testprogs.dir\build

testprogs\CMakeFiles\testprogs.dir\clean:
	cd C:\Users\Red\Documents\sniffer\lpcap\testprogs
	$(CMAKE_COMMAND) -P CMakeFiles\testprogs.dir\cmake_clean.cmake
	cd C:\Users\Red\Documents\sniffer\lpcap
.PHONY : testprogs\CMakeFiles\testprogs.dir\clean

testprogs\CMakeFiles\testprogs.dir\depend:
	$(CMAKE_COMMAND) -E cmake_depends "NMake Makefiles" C:\Users\Red\Documents\sniffer\lpcap C:\Users\Red\Documents\sniffer\lpcap\testprogs C:\Users\Red\Documents\sniffer\lpcap C:\Users\Red\Documents\sniffer\lpcap\testprogs C:\Users\Red\Documents\sniffer\lpcap\testprogs\CMakeFiles\testprogs.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : testprogs\CMakeFiles\testprogs.dir\depend


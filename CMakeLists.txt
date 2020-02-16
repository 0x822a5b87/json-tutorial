cmake_minimum_required(VERSION 3.15)
project(json_tutorial C)

set(CMAKE_C_STANDARD 11)

include_directories(tutorial01)
include_directories(tutorial01_answer)
include_directories(tutorial02)
include_directories(tutorial02_answer)
include_directories(tutorial03)
include_directories(tutorial03_answer)
include_directories(tutorial04)
include_directories(tutorial04_answer)
include_directories(tutorial05)
include_directories(tutorial05_answer)
include_directories(tutorial06)
include_directories(tutorial06_answer)
include_directories(tutorial07)
include_directories(tutorial07_answer)
include_directories(tutorial08)

add_executable(json_tutorial
        tutorial01/leptjson.c
        tutorial01/leptjson.h
        tutorial01/test.c
        tutorial01_answer/leptjson.c
        tutorial01_answer/leptjson.h
        tutorial01_answer/test.c
        tutorial02/leptjson.c
        tutorial02/leptjson.h
        tutorial02/test.c
        tutorial02_answer/leptjson.c
        tutorial02_answer/leptjson.h
        tutorial02_answer/test.c
        tutorial03/leptjson.c
        tutorial03/leptjson.h
        tutorial03/test.c
        tutorial03_answer/leptjson.c
        tutorial03_answer/leptjson.h
        tutorial03_answer/test.c
        tutorial04/leptjson.c
        tutorial04/leptjson.h
        tutorial04/test.c
        tutorial04_answer/leptjson.c
        tutorial04_answer/leptjson.h
        tutorial04_answer/test.c
        tutorial05/leptjson.c
        tutorial05/leptjson.h
        tutorial05/test.c
        tutorial05_answer/leptjson.c
        tutorial05_answer/leptjson.h
        tutorial05_answer/test.c
        tutorial06/leptjson.c
        tutorial06/leptjson.h
        tutorial06/test.c
        tutorial06_answer/leptjson.c
        tutorial06_answer/leptjson.h
        tutorial06_answer/test.c
        tutorial07/leptjson.c
        tutorial07/leptjson.h
        tutorial07/test.c
        tutorial07_answer/leptjson.c
        tutorial07_answer/leptjson.h
        tutorial07_answer/test.c
        tutorial08/leptjson.c
        tutorial08/leptjson.h
        tutorial08/test.c)

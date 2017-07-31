TARGET = libnoirsocks_core.a

CXX = clang++
CXXFLAGS = --std=c++11 -march=native -O3 -pipe

AR = ar -rcs

OBJ := $(patsubst %.cpp,%.o,$(wildcard src/*.cpp))
PROTO_OBJ := $(patsubst %.cpp,%.o,$(wildcard src/protocols/*.cpp))

RM = rm -rfv

INCS = -I./include -I./src

$(TARGET): $(PROTO_OBJ) $(OBJ)
	$(AR) $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCS) -c -o $@ $<

all: $(TARGET)

clean:
	$(RM) $(TARGET) $(OBJ) $(PROTO_OBJ)

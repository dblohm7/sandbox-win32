WIN32LIBS = advapi32.lib user32.lib rpcrt4.lib ole32.lib
CPP_FILES = $(wildcard src/*.cpp)
OBJ_FILES = $(addprefix obj/,$(notdir $(CPP_FILES:.cpp=.obj)))

all : bin bin/proto.exe

bin :
	mkdir $@

obj :
	mkdir $@

obj/%.obj : src/%.cpp obj
	cl -c -Zi -EHsc -MD -DUNICODE -D_UNICODE -DINIT_FUNCTION_NAME=\"$(INIT_FUNCTION)\" -DDEINIT_FUNCTION_NAME=\"$(DEINIT_FUNCTION)\" -I $(LOKI_INCLUDE_PATH) -Fd$(@:.obj=.pdb) -Fo$@ $<

bin/proto.exe : $(OBJ_FILES)
	cl -Zi -MD $^ $(WIN32LIBS) -Fd$(@:.exe=.pdb) -Fe$@

clean :
	rm -rf obj
	rm -rf bin


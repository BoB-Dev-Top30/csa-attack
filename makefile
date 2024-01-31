
CXX = g++

LDLIBS = -lpcap 


all: csa-attack


csa-attack: beacon_frame.o main.o utils.o
	$(CXX) -o csa-attack beacon_frame.o main.o utils.o $(LDLIBS)

%.o: %.cpp
	$(CXX) -c $<

clean:
	rm -f csa-attack *.o


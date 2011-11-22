all: ../proctrace.h child parent

child: child.c ../proctrace.c
	gcc child.c ../proctrace.c -ochild -O3 -g

parent: parent.c ../proctrace.c
	gcc parent.c ../proctrace.c -oparent -O3 -g

clean:
	rm parent child

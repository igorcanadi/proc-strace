all: ../proctrace.h child parent

child: child.c
	gcc child.c -ochild -O3 -g

parent: parent.c
	gcc parent.c -oparent -O3 -g

clean:
	rm parent child

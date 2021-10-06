regview: regview.c
	$(CC) -g $? -o $@

clean:
	rm -f regview

all: regview

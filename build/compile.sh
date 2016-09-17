gcc ../src/*.c -g -o bin/source.out -lpcap -pthread 2>./errors.txt
[ $? -eq 0 ] && echo "Compiled and Linked successfully!" && exit 0
echo "Build failed. Check ./errors.txt"

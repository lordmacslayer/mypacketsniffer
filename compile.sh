gcc sample.c functions.c -g -o sample.out -lpcap 2>./errors.txt
[ $? -eq 0 ] && echo "Compiled and Linked successfully!" && exit 0
echo "Build failed. Check ./errors.txt"

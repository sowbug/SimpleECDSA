//The original header in contained within the sha1.c file, now this file only exposes a simpler method.


/*Returns hash as a string, must be released with free()*/
char* sha1(char* message);

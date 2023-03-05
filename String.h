#ifndef STRING_H_
#define STRING_H_
#include <stdbool.h>

#define ERROR 0
#define OK 1
#define OVERFLOW -1

typedef struct {
	char *ch;
	int length;
} String;

/*generate a string whose value is equal to chars*/
bool StrAssign(String *S, char **chars);

/*return the length of the string*/
unsigned int Length(String S);

/*compare S1 and S2 and if S1 > S2 return 1 else return 0*/
bool Compare(String S1, String S2);

/*empty the string*/
void ClearString(String *S);

/*concat S1 and S2 and return the value using T*/
bool Concat(String *S, String S1, String S2);

/*return a substring of S whose length is len from the position of pos*/
String SubString(String S, int pos, int len);

/*print the string*/
void Traverse(String S);

#endif

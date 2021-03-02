#ifndef COLORS_INCLUDED
#define COLORS_INCLUDED

#define Black 30
#define Red 31
#define Green 32
#define Yellow 33
#define Blue 34
#define Magenta 35
#define Cyan 36
#define White 37
#define reset "\033[0m"

#define print(p) printf("\033[1m\033[%dm", p)
#define refresh() printf("%s", reset)

#endif
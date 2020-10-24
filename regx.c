#include<stdio.h>
#include<regex.h>
#include<string.h>

int is_Host(char *str){
     regex_t regex;

 
     regcomp(&regex, 
        "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
         "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
         "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
         "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$", REG_EXTENDED);
     
    int c= regexec(&regex ,str, 0, NULL, 0);
    return c;

    
    
}

int port_Correct_Format(char *str){
     regex_t regex;

 
     regcomp(&regex, 
        "^((-r)|(-s))$", REG_EXTENDED);
     
    int c= regexec(&regex ,str, 0, NULL, 0);
    return c;

    
    
}
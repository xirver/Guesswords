#define _GNU_SOURCE
#include <stdio.h>
#include <crypt.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>

/*
 *  Macros
 */

//#define DEBUG
#define SALT_SIZE 5
#define MAX_THREADS 8
#define MAX_VALUE_MODIFIERS 256
#define MAX_USER_MODIFIERS 256

/*
 *  Structures
 */

struct passwd_entry {
  char username[7], name[256];
};

struct passwd_entry *passwd;
unsigned int passwd_count;

struct shadow_entry {
  bool cracked;
  char username[7], hash[29];
};

struct shadow_entry *shadow;
unsigned int shadow_count;
char salt[SALT_SIZE + 1];
FILE* dict[MAX_THREADS];
typedef void (* callback)(int, char *);

typedef void (* value_modifier)(char *);
unsigned int value_modifiers_count;
value_modifier value_modifiers[MAX_VALUE_MODIFIERS];
typedef void (* user_modifier)(int);
unsigned int user_modifiers_count;
user_modifier user_modifiers[MAX_USER_MODIFIERS];

/*
 *  Functions
 */

void init_passwd(char *passwd_path);
void init_shadow(char *shadow_path);
void init_dict(char *filename);
void child(int id);
void find_value(char *value, callback callback);
void print(int index, char *value);
void add_value_modifier(value_modifier modifier);
void add_user_modifier(user_modifier modifier);
void leet(char *value);

/*
 *  Modifiers
 */

void default_value_modifier(char *value) {
  find_value(value, print);
}

void default_user_modifier(int index) {
  char *name = passwd[index].name;
  char *p = strchr(name, ' ');
  while (1) {
    // Get name
    unsigned int len = p ? (unsigned int)(p - name) : strlen(name);
    char *temp = (char *)malloc(len + 1);
    memcpy(temp, name, len);
    temp[len] = 0;
    // Try value
    find_value(temp, print);
    // Try lowercase
    for (unsigned int i = 0; i < len; i++) {
      temp[i] = temp[i] | 0x20;
    }
    find_value(temp, print);
    // Try uppercase
    for (unsigned int i = 0; i < len; i++) {
      temp[i] = temp[i] | 0x40;
    }
    find_value(temp, print);
    // Try leet
    leet(temp);
    // Try year
    char *year = (char *)malloc(len + 5);
    for (int i = 1960; i < 2000; i++) {
      snprintf(year, len + 5, "%s%d", temp, i);
      find_value(year, print);
      snprintf(year, len + 5, "%s%d", temp, i - 1900);
      find_value(year, print);
    }
    free(year);
    // Check end
    free(temp);
    if (p == NULL)
      break;
    name = p + 1;
    p = strchr(p + 1, ' ');
  }
}

void leet_replace(char *value, int index) {
  int len = strlen(value);
  switch (value[index]) {
    case 'a': {
      char *temp = (char *)malloc(len + 3);
      temp[len + 2] = 0;
      memcpy(temp, value, index);
      temp[index] = '/';
      temp[index + 1] = '-';
      temp[index + 2] = '\\';
      memcpy(temp + index + 3, value + index + 1, len - index - 1);
      find_value(temp, print);
      memcpy(temp + index + 1, temp + index + 2, len - index + 1);
      find_value(temp, print);
      free(temp);
      break;
    }
    case 'n': {
      char *temp = (char *)malloc(len + 3);
      temp[len + 2] = 0;
      memcpy(temp, value, index);
      temp[index] = '[';
      temp[index + 1] = '\\';
      temp[index + 2] = ']';
      memcpy(temp + index + 3, value + index + 1, len - index - 1);
      find_value(temp, print);
      free(temp);
      break;
    }
    case 'u': {
      char *temp = (char *)malloc(len + 3);
      temp[len + 2] = 0;
      memcpy(temp, value, index);
      temp[index] = '|';
      temp[index + 1] = '_';
      temp[index + 2] = '|';
      memcpy(temp + index + 3, value + index + 1, len - index - 1);
      find_value(temp, print);
      free(temp);      
      break;
    }
    case 'w': {
      char *temp = (char *)malloc(len + 3);
      temp[len + 2] = 0;
      memcpy(temp, value, index);
      temp[index] = '\\';
      temp[index + 1] = '|';
      temp[index + 2] = '/';
      memcpy(temp + index + 3, value + index + 1, len - index - 1);
      find_value(temp, print);
      free(temp);      
      break;
    }
    case 'm': {
      char *temp = (char *)malloc(len + 3);
      temp[len + 2] = 0;
      memcpy(temp, value, index);
      temp[index] = '/';
      temp[index + 1] = 'V';
      temp[index + 2] = '\\';
      memcpy(temp + index + 3, value + index + 1, len - index - 1);
      find_value(temp, print);
      free(temp);
      break;
    }
    case 'd': {
      char *temp = (char *)malloc(len + 2);
      temp[len + 1] = 0;
      memcpy(temp, value, index);
      temp[index] = '|';
      temp[index + 1] = ')';
      memcpy(temp + index + 2, value + index + 1, len - index - 1);
      find_value(temp, print);
      temp[index] = '[';
      find_value(temp, print);
      free(temp);
      break;
    }
    case 'o': {
      char *temp = (char *)malloc(len + 2);
      temp[len + 1] = 0;
      memcpy(temp, value, index);
      temp[index] = '(';
      temp[index + 1] = ')';
      memcpy(temp + index + 2, value + index + 1, len - index - 1);
      find_value(temp, print);
      temp[index] = '\xA7';
      memcpy(temp + index + 1, temp + index + 2, len - index + 1);
      find_value(temp, print);
      free(temp);
      break;
    }
    case 'p': {
      char *temp = (char *)malloc(len + 2);
      temp[len + 1] = 0;
      memcpy(temp, value, index);
      temp[index] = '|';
      temp[index + 1] = '>';
      memcpy(temp + index + 2, value + index + 1, len - index - 1);
      find_value(temp, print);
      free(temp);
      break;  
    }
    case 'j': {
      char *temp = (char *)malloc(len + 2);
      temp[len + 1] = 0;
      memcpy(temp, value, index);
      temp[index] = '(';
      temp[index + 1] = '/';
      memcpy(temp + index + 2, value + index + 1, len - index - 1);
      find_value(temp, print);
      temp[index] = ']';
      memcpy(temp + index + 1, temp + index + 2, len - index + 1);
      find_value(temp, print);
      free(temp);
      break;  
    }
    case 'y': {
      char *temp = (char *)malloc(len + 2);
      temp[len + 1] = 0;
      memcpy(temp, value, index);
      temp[index] = '\\';
      temp[index + 1] = '\'';
      memcpy(temp + index + 2, value + index + 1, len - index - 1);
      find_value(temp, print);
      temp[index] = '`';
      temp[index + 1] = '/';
      find_value(temp, print);      
      free(temp);
      break;     
    }
    case 'v': {
      char *temp = (char *)malloc(len + 2);
      temp[len + 1] = 0;
      memcpy(temp, value, index);
      temp[index] = '`';
      temp[index + 1] = '\'';
      memcpy(temp + index + 2, value + index + 1, len - index - 1);
      find_value(temp, print);
      free(temp);
      break;  
    }
    case 'k': {
      char *temp = (char *)malloc(len + 2);
      temp[len + 1] = 0;
      memcpy(temp, value, index);
      temp[index] = '|';
      temp[index + 1] = '(';
      memcpy(temp + index + 2, value + index + 1, len - index - 1);
      find_value(temp, print);
      free(temp);
      break;  
    }
    case 'c': {
      char *temp = (char *)malloc(len + 1);
      temp[len] = 0;
      memcpy(temp, value, len);
      temp[index] = '<';
      find_value(temp, print);
      free(temp);
      break;  
    }
    case 'i': {
      char *temp = (char *)malloc(len + 1);
      temp[len] = 0;
      memcpy(temp, value, len);
      temp[index] = '!';
      find_value(temp, print);
      free(temp);
      break;  
    }
    case 'g': {
      char *temp = (char *)malloc(len + 1);
      temp[len] = 0;
      memcpy(temp, value, len);
      temp[index] = '&';
      find_value(temp, print);
      free(temp);
      break;
    }
    case 'e': {
      char *temp = (char *)malloc(len + 1);
      temp[len] = 0;
      memcpy(temp, value, len);
      temp[index] = '3';
      find_value(temp, print);
      free(temp);
      break;  
    }
    case 't': {
      char *temp = (char *)malloc(len + 1);
      temp[len] = 0;
      memcpy(temp, value, len);
      temp[index] = '7';
      find_value(temp, print);
      free(temp);
      break;  
    }
  }
}

int is_leet(char c) {
  switch (c) {
    case 'a':
    case 'n':
    case 'u':
    case 'w':
    case 'm':
    case 'd':
    case 'o':
    case 'p':
    case 'j':
    case 'y':
    case 'v':
    case 'k':
    case 'c':
    case 'i':
    case 'g':
    case 'e':
    case 't': {
      return 1;
    }
    default: {
      return 0;
    }
  }
}

void leet(char *value) {
  int len = strlen(value);
  for (int i = 0; i < len; i++) {
    if (is_leet(value[i])) {
      leet_replace(value, i);
    }
  }
}

/*
 *  Function definitions
 */

int main(int argc, char *argv[]) {
  (void) argc;
  // Initialize
  init_passwd(argv[1]);
  init_shadow(argv[2]);
  init_dict("dict2.txt");
  //default_user_modifier(0);
  //return 0;

  add_value_modifier(default_value_modifier);
  add_user_modifier(default_user_modifier);

  // Create threads
  pthread_t threads[MAX_THREADS];
  void *thread_id = NULL;
  for (int i = 0; i < MAX_THREADS; i++) {
    pthread_create(&threads[i], NULL, (void *(*)(void *))child, thread_id);
    thread_id++;
  }
  for (int i = 0; i < MAX_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
}

void init_passwd(char *passwd_path) {
  char line[256];
  FILE *fp = fopen(passwd_path, "r");
  while (!feof(fp)) {
    line[0] = 0;
    if(fgets(line, sizeof(line), fp)!=NULL)
    if (line[0] == 0)
      break;
    passwd_count++;
  }
  fseek(fp, 0, SEEK_SET);
  passwd = (struct passwd_entry *)calloc(passwd_count, sizeof(struct passwd_entry));
  for (unsigned int i = 0; i < passwd_count; i++) {
    if(fgets(line, sizeof(line), fp)!=NULL)
    memcpy(passwd[i].username, line, 6);
    char *begin = line, *end;
    for (int j = 0; j < 4; j++)
      begin = strchr(begin, ':') + 1;
    end = strstr(begin, ",,,:");
    unsigned int size = end - begin;
    if (size < sizeof(passwd[i].name)) {
      memcpy(passwd[i].name, begin, size);
      
    }
  }
  fclose(fp);
}

void init_shadow(char *shadow_path) {
  char line[256];
  FILE *fp = fopen(shadow_path, "r");
  while (!feof(fp)) {
    line[0] = 0;
    if(fgets(line, sizeof(line), fp)!=NULL)
    if (line[0] == 0)
      break;
    shadow_count++;
  }
  fseek(fp, 0, SEEK_SET);
  memset(salt, 0, SALT_SIZE + 1); 
  if(fgets(line, sizeof(line), fp)!=NULL)
  memcpy(salt, line + 7, SALT_SIZE);
  fseek(fp, 0, SEEK_SET);
  shadow = (struct shadow_entry *)calloc(shadow_count, sizeof(struct shadow_entry));
  for (unsigned int i = 0; i < shadow_count; i++) {
    if(fgets(line, sizeof(line), fp)!=NULL)
    memcpy(shadow[i].username, line, 6);
    char *begin = strchr(line, ':') + 1, *end = strchr(begin, ':');
    unsigned int size = end - begin;
    if (size < sizeof(shadow[i].hash)) {
      memcpy(shadow[i].hash, begin, size);
    }
  }

  fclose(fp);

}

void init_dict(char *filename) {
  unsigned int line_number = 0;
  FILE *fp = fopen(filename, "r");
  char line[256];

  while (!feof(fp)) {

    if(fgets(line, sizeof(line), fp)!=NULL)

    line_number++;
  }
  fseek(fp, 0, SEEK_SET);
  int i = 0;

  for (int i = 0; i < MAX_THREADS; i++) {
    char file_name[10];
    sprintf(file_name, "%d.txt", i);
    dict[i] = fopen(file_name, "w+");
  }


  while (!feof(fp)) {
    line[0] = 0;
    if(fscanf(fp, "%s", line))
    if (line[0] == 0)
      break;
    fprintf(dict[i], "%s\n", line);
    if (i == (MAX_THREADS - 1)) i = 0;
    else i++;
  }
  for (i = 0; i < MAX_THREADS; i++) {
    fseek(dict[i], 0, SEEK_SET);
  }
  fclose(fp);
}

/*
 *  Checks all the values in the designated dictionary if they match any password hash.
 */
void child(int id) {
  FILE *fp = dict[id];
  while (!feof(fp)) {
    char value[256];
    value[0] = 0;
    if(fscanf(fp, "%s", value))
    if (value[0] == 0)
      break;
    for (unsigned int i = 0; i < value_modifiers_count; i++) {
      value_modifiers[i](value);
    }
  }
  fclose(fp);
  for (unsigned int i = id * (passwd_count / MAX_THREADS); i < (id + 1) * (passwd_count / MAX_THREADS); i++) {
    for (unsigned int j = 0; j < user_modifiers_count; j++) {
      user_modifiers[j](i);
    }  
  }
}

/*
 *  Hashes and looks up a value in the shadow table. If the value is found, callback is called with the index where the value was found, and the value itself as arguemnts.
 */
void find_value(char *value, callback callback) {
  //printf("%s\n", value);
  //return;

  struct crypt_data data;
  data.initialized = 0;
  char *hash = crypt_r(value, salt, &data);
  for (unsigned int i = 0; i < shadow_count; i++) {
    if (shadow[i].cracked == false && !memcmp(hash, shadow[i].hash, sizeof(shadow[i].hash))) {
      shadow[i].cracked = true;
      callback(i, value);
    }
  }
}

/*
 *  Prints the information of the users for which the password has been cracked.
 */
void print(int index, char *value) {
#ifdef DEBUGS
  printf("%s\n", shadow[index].username);
#else
  printf("%s:%s\n", shadow[index].username, value);
#endif
}

void add_value_modifier(value_modifier modifier) {
  if (value_modifiers_count == MAX_VALUE_MODIFIERS)
    return;
  value_modifiers[value_modifiers_count++] = modifier;
}

void add_user_modifier(user_modifier modifier) {
  if (user_modifiers_count == MAX_USER_MODIFIERS)
    return;
  user_modifiers[user_modifiers_count++] = modifier;
}


#include <stdlib.h>

#include "list.h"
#include "stack.h"

/****************************************************************
 *                                                              *
 *  ----------------------- stack_push -----------------------  *
 *                                                              *
 ***************************************************************/

int stack_push(Stack *pile, const void *donnee) {
return list_ins_next(pile, NULL, donnee);
}

/****************************************************************
 *                                                              *
 *  ----------------------- stack_pop ------------------------  *
 *                                                              *
 ***************************************************************/

int stack_pop(Stack *pile, void **donnee) {
return list_rem_next(pile, NULL, donnee);
}

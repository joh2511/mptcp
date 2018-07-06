#ifndef _MPTCP_RBS_DYNARRAY_H
#define _MPTCP_RBS_DYNARRAY_H

#include <linux/slab.h>
#include <linux/string.h>

#define DECL_DA(name, item_type)                                               \
	struct name {                                                          \
		item_type *items;                                              \
		int len;                                                       \
		int capacity;                                                  \
	}

#define INIT_DA(array)                                                         \
	do {                                                                   \
		(array)->items = NULL;                                         \
		(array)->len = 0;                                              \
		(array)->capacity = 0;                                         \
	} while (0)

#define FREE_DA(array) kfree((array)->items)

#define ADD_DA_ITEM(array, item) INSERT_DA_ITEM(array, (array)->len, item)

#define ADD_DA_ITEM_EX(array, item, grow_func)                                 \
	INSERT_DA_ITEM_EX(array, (array)->len, item, grow_func)

#define INSERT_DA_ITEM(array, index, item)                                     \
	INSERT_DA_ITEM_EX(array, index, item,                                  \
			  !(array)->capacity ? 8 : (array)->capacity << 1)

#define INSERT_DA_ITEM_EX(array, index, item, grow_func)                       \
	do {                                                                   \
		if ((array)->len == (array)->capacity) {                       \
			(array)->capacity = grow_func;                         \
			(array)->items = krealloc((array)->items,              \
						  sizeof((array)->items[0]) *  \
						      (array)->capacity,       \
						  GFP_KERNEL);                 \
		}                                                              \
									       \
		if ((index) != (array)->len)                                   \
			memmove(&(array)[index + 1], &(array)[index],          \
				((array)->len - (index)) *                     \
				    sizeof((array)->items[0]));                \
		(array)->items[index] = item;                                  \
		++(array)->len;                                                \
	} while (0)

#define DELETE_DA_ITEM(array, index)                                           \
	do {                                                                   \
		BUG_ON((index) < 0);                                           \
		BUG_ON((index) >= (array)->len);                               \
									       \
		if ((index) < (array)->len - 1)                                \
			memmove((array)->items[index],                         \
				(array)->items[(index) + 1],                   \
				((array)->len - 1 - (index)) *                 \
				    sizeof((array)->items[0]));                \
									       \
		--(array)->len;                                                \
	} while (0)

#define GET_DA_LEN(array) (array)->len

#define GET_DA_ITEM(array, index)                                              \
	({                                                                     \
		BUG_ON(index < 0 || index >= (array)->len);                    \
		(array)->items[index];                                         \
	})

#define FOREACH_DA_ITEM(array, var, cmds)                                      \
	do {                                                                   \
		typeof(var) *__item = (array)->items;                          \
		typeof(var) *__end = (array)->items + (array)->len;            \
		while (__item != __end) {                                      \
			var = *__item;                                         \
			++__item;                                              \
			cmds;                                                  \
		}                                                              \
	} while (0)

#define FOREACH_DA_ITEM_REV(array, var, cmds)                                  \
	do {                                                                   \
		typeof(var) *__item = (array)->items + (array)->len - 1;       \
		typeof(var) *__end = (array)->items - 1;                       \
		while (__item != __end) {                                      \
			var = *__item;                                         \
			--__item;                                              \
			cmds;                                                  \
		}                                                              \
	} while (0)

#endif

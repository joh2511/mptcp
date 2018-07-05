#ifndef MULTIPLATFORM_H 
#define MULTIPLATFORM_H 

#define RBS_STATS

#ifdef RBS_STATS
	#define RBS_DO_STAT(stat, value) rbs_stats_update(stat, value);
#else
#define RBS_DO_STAT(stat, value) // nothing to do
#endif

#define ALLOC(struct_name) kzalloc(sizeof(struct struct_name), GFP_ATOMIC);
#define FREE(instance) kfree(instance);

#include <linux/types.h>
#include <linux/slab.h>

#endif

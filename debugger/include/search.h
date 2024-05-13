#pragma once

#include <ps4.h>

#define MAX_DUMP_SIZE 0x80000 //512kb buffer //0x100000

/*
 * Struct:  inputSearchStart
 * --------------------
 *
 *	processId:		4 Bytes | The process id.
 *	startAddress:	8 Bytes | The memory address you want to start searching from.
 *	endAddress:		8 Bytes | The memory address you want to finish searching at.
 *	length:			4 Bytes | The number of bytes you want to search for.
 */
struct inputSearchStart;

/*
 * Struct:  inputSearchRescan
 * --------------------
 *
 *	processId:		4 Bytes | The process id.
 *	length:			4 Bytes | The number of bytes you want to search for.
 */
struct inputSearchRescan;

/*
 * Struct:  searchResults
 * --------------------
 *
 *	items:	The results.
 *	count:	The number of items.
 *	size:	The total number of items that can be in this array.
 */
struct searchResults
{
	uint64_t *items;
	size_t countTotal;
	size_t count;
	size_t size;
};
extern struct searchResults results;

/*
 * enum:  SearchState
 * --------------------
 *
 *	STARTED:	If the search has been started and results are allocated.
 *	ENDED:		If the search has finished and results have been freed.
 */
enum SearchState
{
	STARTED = 1,
	ENDED,
};
extern enum SearchState state;

void write_pending_results_to_file();

/*
 * Function:  allocate_results
 * --------------------
 * Allocate the results data set.
 *
 *	sResults:		The results struct to be allocated.
 *	initialSize:	The initial number of elements the array should be allocated for.
 */
void allocate_results(struct searchResults *sResults, size_t initialSize);

/*
 * Function:  add_result
 * --------------------
 * Add a result address to the list of results.
 *
 *	sResults:		The results struct.
 *	result:			The result address to be added to the results.
 */
void add_result(struct searchResults *sResults, uint64_t result);

/*
 * Function:  remove_result
 * --------------------
 * Remove a result from the list of results.
 * Note: You must run cleanResults after this function. (Or after the loop of using this funciton) to fix the array.
 *
 *	sResults:		The results struct.
 *	index:			The index of the results array to be removed.
 */
void remove_result(struct searchResults *sResults, uint32_t index);

/*
 * Function:  clean_results
 * --------------------
 * Re-calibrate the array by removing NULL values.
 *
 *	sResults:		The results struct.
 */
void clean_results(struct searchResults *sResults);

/*
 * Function:  free_results
 * --------------------
 * Free the results allocated resources.
 *
 *	sResults:		The results struct to be freed.
 */
void free_results(struct searchResults *sResults);

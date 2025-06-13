#ifndef _MSE_DEBUG_H
#define _MSE_DEBUG_H

#include "mse_status.h"

void mse_trace_config(FILE* fp);

MSE_STATUS mse_trace(MSE_STATUS status);
MSE_STATUS mse_trace_msg(MSE_STATUS status, const char * msg);

#endif /* _MSE_DEBUG_H */

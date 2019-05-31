#ifndef __LOGGER_H__
#define __LOGGER_H__

#include "logger_def.h"

extern logger *logger_;

#define LOG_ERROR logger_->log(logger_entry::level::error)
#define LOG_WARN logger_->log(logger_entry::level::warn)
#define LOG_INFO logger_->log(logger_entry::level::info)
#define LOG_DEBUG logger_->log(logger_entry::level::debug)


#endif

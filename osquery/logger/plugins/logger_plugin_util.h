/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/dispatcher.h>
#include <osquery/logger.h>

namespace osquery {

static inline void iterate(std::vector<std::string>& input,
                           std::function<void(std::string&)> predicate) {
  // Since there are no 'multi-do' APIs, keep a count of consecutive actions.
  // This count allows us to sleep the thread to prevent utilization thrash.
  size_t count = 0;
  for (auto& item : input) {
    // The predicate is provided a mutable string.
    // It may choose to clear/move the data.
    predicate(item);
    if (++count % 100 == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
}

/**
 * @brief A log forwarder thread flushing database-buffered logs.
 *
 * The BufferedLogForwarderRunner flushes buffered result and status logs based
 * on CLI/options settings. If an enrollment key is set (and checked) during
 * startup, this Dispatcher service is started.
 */
class BufferedLogForwarderRunner : public InternalRunnable {
 private:
  static const time_t kLogPeriod;
  static const size_t kMaxLogLines;

 public:
  explicit BufferedLogForwarderRunner()
      : logPeriod_(kLogPeriod), maxLogLines_(kMaxLogLines) {}

  /// A simple wait lock, and flush based on settings.
  void start() override;

 protected:
  /**
   * @brief Send labeled result logs.
   *
   * The log_data provided to send must be mutable.
   * To optimize for smaller memory, this will be moved into place within the
   * constructed property tree before sending.
   */
  virtual Status send(std::vector<std::string>& log_data,
                      const std::string& log_type) = 0;

  /**
   * @brief Check for new logs and send.
   *
   * Scan the logs domain for up to 1024 log lines.
   * Sort those lines into status and request types then forward (send) each
   * set. On success, clear the data and indexes.
   */
  void check();

  /// Seconds between flushing logs
  time_t logPeriod_;

  /// Max number of logs to flush per check
  size_t maxLogLines_;

 private:
  friend class BufferedLoggerTests;
};
}

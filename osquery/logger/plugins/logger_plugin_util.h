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

#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

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
 * This is a base class intended to provide reliable buffering and sending of
 * status and result logs. Subclasses may take advantage of this reliable
 * sending logic, and implement their own methods for actually sending logs.
 *
 * Subclasses must define the send() method
 */
class BufferedLogForwarder : public InternalRunnable {
 protected:
  static const std::chrono::seconds kLogPeriod;
  static const size_t kMaxLogLines;

 protected:
  // These constructors are made available for subclasses to use, but
  // subclasses should expose appropriate constructors to their users.
  explicit BufferedLogForwarder(const std::string& name)
      : logPeriod_(kLogPeriod),
        maxLogLines_(kMaxLogLines),
        logIndex_(0),
        indexName_(name) {}

  template <class Rep, class Period>
  explicit BufferedLogForwarder(
      const std::string& name,
      const std::chrono::duration<Rep, Period>& log_period)
      : logPeriod_(
            std::chrono::duration_cast<std::chrono::seconds>(log_period)),
        maxLogLines_(kMaxLogLines),
        logIndex_(0),
        indexName_(name) {}

  template <class Rep, class Period>
  explicit BufferedLogForwarder(
      const std::string& name,
      const std::chrono::duration<Rep, Period>& log_period,
      size_t max_log_lines)
      : logPeriod_(
            std::chrono::duration_cast<std::chrono::seconds>(log_period)),
        maxLogLines_(max_log_lines),
        logIndex_(0),
        indexName_(name) {}

 public:
  /// A simple wait lock, and flush based on settings.
  void start() override;

  Status logString(const std::string& s);

  Status logStatus(const std::vector<StatusLogLine>& log);

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

  std::string genLogIndex(bool results);

  /// Seconds between flushing logs
  std::chrono::seconds logPeriod_;

  /// Max number of logs to flush per check
  size_t maxLogLines_;

  /// Hold an incrementing index for buffering logs
  size_t logIndex_;

  /**
   * @brief Name to use in index
   *
   * This name is used so that loggers of different types that are operating
   * simultaneously can separately maintain their buffer of logs.
   */
  std::string indexName_;
};
}

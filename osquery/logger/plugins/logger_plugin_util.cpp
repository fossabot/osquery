/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <thread>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/logger/plugins/logger_plugin_util.h"

namespace pt = boost::property_tree;

namespace osquery {

const time_t BufferedLogForwarderRunner::kLogPeriod = 4;
const size_t BufferedLogForwarderRunner::kMaxLogLines = 1024;

void BufferedLogForwarderRunner::check() {
  // Get a list of all the buffered log items, with a max of 1024 lines.
  std::vector<std::string> indexes;
  auto status = scanDatabaseKeys(kLogs, indexes, maxLogLines_);

  // For each index, accumulate the log line into the result or status set.
  std::vector<std::string> results, statuses;
  iterate(indexes, ([&results, &statuses](std::string& index) {
            std::string value;
            auto& target = ((index.at(0) == 'r') ? results : statuses);
            if (getDatabaseValue(kLogs, index, value)) {
              target.push_back(std::move(value));
            }
          }));

  // If any results/statuses were found in the flushed buffer, send.
  if (results.size() > 0) {
    status = send(results, "result");
    if (!status.ok()) {
      VLOG(1) << "Error sending results to logger: " << status.getMessage();
    } else {
      // Clear the results logs once they were sent.
      iterate(indexes, ([&results](std::string& index) {
                if (index.at(0) != 'r') {
                  return;
                }
                deleteDatabaseValue(kLogs, index);
              }));
    }
  }

  if (statuses.size() > 0) {
    status = send(statuses, "status");
    if (!status.ok()) {
      VLOG(1) << "Error sending status to logger: " << status.getMessage();
    } else {
      // Clear the status logs once they were sent.
      iterate(indexes, ([&results](std::string& index) {
                if (index.at(0) != 's') {
                  return;
                }
                deleteDatabaseValue(kLogs, index);
              }));
    }
  }
}

void BufferedLogForwarderRunner::start() {
  while (!interrupted()) {
    check();

    // Cool off and time wait the configured period.
    pauseMilli(logPeriod_);
  }
}
}

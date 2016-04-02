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

#include <osquery/database.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/config/parsers/decorators.h"
#include "osquery/logger/plugins/logger_plugin_util.h"

namespace pt = boost::property_tree;

namespace osquery {

const auto BufferedLogForwarderRunner::kLogPeriod = std::chrono::seconds(4);
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

Status BufferedLogForwarderRunner::logString(const std::string& s) {
  std::string index = genLogIndex(true);
  return setDatabaseValue(kLogs, index, s);
}

Status BufferedLogForwarderRunner::logStatus(
    const std::vector<StatusLogLine>& log) {
  // Append decorations to status (unique to TLS logger).
  // Assemble a decorations tree to append to each status buffer line.
  pt::ptree dtree;
  std::map<std::string, std::string> decorations;
  getDecorations(decorations);
  for (const auto& decoration : decorations) {
    dtree.put(decoration.first, decoration.second);
  }

  for (const auto& item : log) {
    // Convert the StatusLogLine into ptree format, to convert to JSON.
    pt::ptree buffer;
    buffer.put("severity", (google::LogSeverity)item.severity);
    buffer.put("filename", item.filename);
    buffer.put("line", item.line);
    buffer.put("message", item.message);
    if (decorations.size() > 0) {
      buffer.put_child("decorations", dtree);
    }

    // Convert to JSON, for storing a string-representation in the database.
    std::string json;
    try {
      std::stringstream json_output;
      pt::write_json(json_output, buffer, false);
      json = json_output.str();
    } catch (const pt::json_parser::json_parser_error& e) {
      // The log could not be represented as JSON.
      return Status(1, e.what());
    }

    // Store the status line in a backing store.
    if (!json.empty()) {
      json.pop_back();
    }
    std::string index = genLogIndex(false);
    Status status = setDatabaseValue(kLogs, index, json);
    if (!status.ok()) {
      // Do not continue if any line fails.
      return status;
    }
  }

  return Status(0, "OK");
}

std::string BufferedLogForwarderRunner::genLogIndex(bool results) {
  return ((results) ? "r" : "s") + std::string("_") + indexName_ + "_" +
         std::to_string(getUnixTime()) + "_" + std::to_string(++logIndex_);
}
}

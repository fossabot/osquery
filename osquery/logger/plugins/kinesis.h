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

#include <vector>

#include <aws/kinesis/KinesisClient.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>

namespace osquery {

class KinesisLoggerPlugin : public LoggerPlugin {
 public:
 KinesisLoggerPlugin() : LoggerPlugin(), client_() {
    shardId_ = getHostIdentifier();
  }

  Status init(const std::string& name,
              const std::vector<StatusLogLine>& log) override;


  Status logString(const std::string& s) override;

 private:
  Aws::Kinesis::KinesisClient client_;
  std::string shardId_;
};
}

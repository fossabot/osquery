/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"
#include "osquery/logger/plugins/logger_plugin_util.h"

namespace osquery {

class LoggerPluginUtilTests : public testing::Test {};

class MockBufferedLogForwarderRunner : public BufferedLogForwarderRunner {
 public:
  MOCK_METHOD2(send,
      Status(std::vector<std::string>& log_data, const std::string& log_type));
};

TEST_F(LoggerPluginUtilTests, test_buffered_log_forwarder_runner) {
  auto runner = std::make_shared<MockBufferedLogForwarderRunner>();
  Dispatcher::addService(runner);
  EXPECT_CALL(*runner, send({}, ""));
}
}

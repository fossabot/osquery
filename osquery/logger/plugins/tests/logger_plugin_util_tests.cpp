/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>

#include "osquery/core/test_util.h"
#include "osquery/logger/plugins/logger_plugin_util.h"

namespace osquery {

class LoggerPluginUtilTests : public testing::Test {};

class TestLogForwarderRunner : public BufferedLogForwarderRunner {};

TEST_F(LoggerPluginUtilTests, test_buffered_log_forwarder_runner) {
  ASSERT_TRUE(true);
}
}

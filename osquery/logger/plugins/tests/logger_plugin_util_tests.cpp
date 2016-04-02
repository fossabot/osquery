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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"
#include "osquery/logger/plugins/logger_plugin_util.h"

namespace osquery {

using namespace testing;

class LoggerPluginUtilTests : public Test {
 public:
  void SetUp() {
    // shutdownTesting();
    initTesting();
  }
};

class MockBufferedLogForwarderRunner : public BufferedLogForwarderRunner {
 public:
  MockBufferedLogForwarderRunner() : BufferedLogForwarderRunner("mock") {}

  MOCK_METHOD2(send,
      Status(std::vector<std::string>& log_data, const std::string& log_type));
  FRIEND_TEST(LoggerPluginUtilTests, test_buffered_log_forwarder_index);
  FRIEND_TEST(LoggerPluginUtilTests, test_buffered_log_forwarder_basic);
  FRIEND_TEST(LoggerPluginUtilTests, test_buffered_log_forwarder_retry);
};

TEST_F(LoggerPluginUtilTests, test_buffered_log_forwarder_index) {
  MockBufferedLogForwarderRunner runner;
  EXPECT_THAT(runner.genLogIndex(true), ContainsRegex("r_mock_[0-9]+_1"));
  EXPECT_THAT(runner.genLogIndex(true), ContainsRegex("r_mock_[0-9]+_2"));
  EXPECT_THAT(runner.genLogIndex(true), ContainsRegex("r_mock_[0-9]+_3"));
}

TEST_F(LoggerPluginUtilTests, test_buffered_log_forwarder_basic) {
  StrictMock<MockBufferedLogForwarderRunner> runner;
  runner.logString("foo");

  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner.check();
  // This call should not result in sending again
  runner.check();

  runner.logString("bar");
  runner.logString("baz");
  EXPECT_CALL(runner, send(ElementsAre("bar", "baz"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner.check();
  // This call should not result in sending again
  runner.check();
}

TEST_F(LoggerPluginUtilTests, test_buffered_log_forwarder_retry) {
  StrictMock<MockBufferedLogForwarderRunner> runner;
  runner.logString("foo");

  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner.check();

  // This call should try to send again because the first failed
  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner.check();

  runner.logString("bar");
  EXPECT_CALL(runner, send(ElementsAre("foo", "bar"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner.check();

  // This call should not send again because the previous was successful
  runner.check();
}

TEST_F(LoggerPluginUtilTests, test_buffered_log_forwarder_async) {
  auto runner = std::make_shared<MockBufferedLogForwarderRunner>();
  Dispatcher::addService(runner);

  EXPECT_CALL(*runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner->logString("foo");
  std::this_thread::sleep_for(std::chrono::seconds(6));

  Dispatcher::stopServices();
  Dispatcher::joinServices();

  // // Second call should try to send again because the first failed
  // EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
  //   .WillOnce(Return(Status(1, "fail")));
  // runner.check();

  // runner.logString("bar");
  // EXPECT_CALL(runner, send(ElementsAre("foo", "bar"), "result"))
  //   .WillOnce(Return(Status(0, "OK")));
  // runner.check();

  // // This call should not send again because the previous was successful
  // runner.check();
}
}

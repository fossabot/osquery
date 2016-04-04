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
    initTesting();
  }
};

class MockBufferedLogForwarderRunner : public BufferedLogForwarderRunner {
 public:
  using BufferedLogForwarderRunner::BufferedLogForwarderRunner;
  MockBufferedLogForwarderRunner() : BufferedLogForwarderRunner("mock") {}

  MOCK_METHOD2(send,
      Status(std::vector<std::string>& log_data, const std::string& log_type));
  FRIEND_TEST(LoggerPluginUtilTests, test_buffered_log_forwarder_index);
  FRIEND_TEST(LoggerPluginUtilTests, test_buffered_log_forwarder_basic);
  FRIEND_TEST(LoggerPluginUtilTests, test_buffered_log_forwarder_retry);
  FRIEND_TEST(LoggerPluginUtilTests, test_buffered_log_forwarder_async);
  FRIEND_TEST(LoggerPluginUtilTests, test_buffered_log_forwarder_split);
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
  auto runner = std::make_shared<StrictMock<MockBufferedLogForwarderRunner>>(
      "mock", std::chrono::milliseconds(100));
  Dispatcher::addService(runner);

  EXPECT_CALL(*runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner->logString("foo");
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  EXPECT_CALL(*runner, send(ElementsAre("bar"), "result"))
      .Times(3)
      .WillOnce(Return(Status(1, "fail")))
      .WillOnce(Return(Status(1, "fail again")))
      .WillOnce(Return(Status(0, "OK")));
  runner->logString("bar");
  std::this_thread::sleep_for(std::chrono::milliseconds(350));

  // Sleep at least a whole period at the end to make sure there are no
  // unexpected calls
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  Dispatcher::stopServices();
  Dispatcher::joinServices();
}

TEST_F(LoggerPluginUtilTests, test_buffered_log_forwarder_split) {
  StrictMock<MockBufferedLogForwarderRunner> runner(
      "mock", std::chrono::milliseconds(100), 1);
  runner.logString("foo");
  runner.logString("bar");
  runner.logString("baz");

  // Expect that all three calls are sent separately
  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner.check();

  EXPECT_CALL(runner, send(ElementsAre("foo"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner.check();

  EXPECT_CALL(runner, send(ElementsAre("bar"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner.check();

  EXPECT_CALL(runner, send(ElementsAre("baz"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner.check();

  StrictMock<MockBufferedLogForwarderRunner> runner2(
      "mock", std::chrono::milliseconds(100), 2);
  runner2.logString("foo");
  runner2.logString("bar");
  runner2.logString("baz");

  // Expect that the first two are sent together
  EXPECT_CALL(runner2, send(ElementsAre("foo", "bar"), "result"))
      .WillOnce(Return(Status(1, "fail")));
  runner2.check();

  EXPECT_CALL(runner2, send(ElementsAre("foo", "bar"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner2.check();

  // Then the last when the first two are successful
  EXPECT_CALL(runner2, send(ElementsAre("baz"), "result"))
      .WillOnce(Return(Status(0, "OK")));
  runner2.check();
}
}

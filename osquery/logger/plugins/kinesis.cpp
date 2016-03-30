/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <aws/core/Version.h>

#include <osquery/flags.h>
#include <osquery/registry.h>

#include <aws/kinesis/model/PutRecordRequest.h>
#include <aws/kinesis/model/PutRecordResult.h>
#include <aws/kinesis/model/ListStreamsRequest.h>
#include <aws/kinesis/model/ListStreamsResult.h>
#include <aws/core/client/AWSClient.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/Outcome.h>

#include <boost/spirit.hpp>

#include "osquery/logger/plugins/kinesis.h"

namespace osquery {

REGISTER(KinesisLoggerPlugin, "logger", "kinesis");

Status KinesisLoggerPlugin::logString(const std::string& s) {
  VLOG(1) << "KinesisLog: " << s;

  Aws::Kinesis::Model::ListStreamsRequest r;
  auto result = client_.ListStreams(r).GetResult();
  VLOG(1) << result.GetStreamNames().size();

  Aws::Kinesis::Model::PutRecordRequest request;
  request.WithStreamName("osquery_test")
    .WithPartitionKey(shardId_)
    .WithData(Aws::Utils::ByteBuffer((unsigned char*)s.c_str(), s.length()));

  VLOG(1) << "About to put...";
  Aws::Kinesis::Model::PutRecordOutcome outcome = client_.PutRecord(request);
  if (outcome.IsSuccess()) {
    VLOG(1) << "Success!";
    return Status(0, "OK");
  } else {
    VLOG(1) << "Failed with error " << outcome.GetError().GetMessage();
    return Status(1, outcome.GetError().GetMessage());
  }

  return Status(0, "OK");
}

}

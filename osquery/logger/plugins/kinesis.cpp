/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>

#include <osquery/flags.h>
#include <osquery/registry.h>

#include <aws/core/client/AWSClient.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/Outcome.h>
#include <aws/iam/IAMClient.h>
#include <aws/iam/model/GetUserRequest.h>
#include <aws/iam/model/GetUserResult.h>
#include <aws/kinesis/model/ListStreamsRequest.h>
#include <aws/kinesis/model/ListStreamsResult.h>
#include <aws/kinesis/model/PutRecordRequest.h>
#include <aws/kinesis/model/PutRecordResult.h>

#include <boost/algorithm/string/join.hpp>

#include "osquery/logger/plugins/kinesis.h"

namespace osquery {

REGISTER(KinesisLoggerPlugin, "logger", "kinesis");

FLAG(string, aws_kinesis_stream, "", "Name of Kinesis stream for logging")

Status KinesisLoggerPlugin::setUp() {
  VLOG(1) << "KinesisLoggerPlugin::setUp()";
  shardId_ = getHostIdentifier();

  Aws::Kinesis::Model::ListStreamsRequest r;
  auto result = client_.ListStreams(r).GetResult();
  std::vector<std::string> stream_names = result.GetStreamNames();
  VLOG(1) << "Listing " << stream_names.size() << " found streams: ";
  VLOG(1) << boost::algorithm::join(stream_names, ", ");

  if (FLAGS_aws_kinesis_stream.empty()) {
    std::string err =
        "Stream name must be specified with --aws_kinesis_stream=";
    LOG(WARNING) << err;
    return Status(1, err);
  }

  if (std::find(stream_names.begin(),
                stream_names.end(),
                FLAGS_aws_kinesis_stream) == stream_names.end()) {
    Aws::IAM::IAMClient iam_client;
    auto user = iam_client.GetUser(Aws::IAM::Model::GetUserRequest())
                    .GetResult()
                    .GetUser();
    std::string err = "Could not find stream with name: " +
                      FLAGS_aws_kinesis_stream + " for user " +
                      user.GetUserName() + "(" + user.GetUserId() + ")";
    LOG(WARNING) << err;
    return Status(1, err);
  }
  VLOG(1) << "Found specified stream: " << FLAGS_aws_kinesis_stream;
  return Status(0, "OK");
}

Status KinesisLoggerPlugin::logString(const std::string& s) {
  Aws::Kinesis::Model::PutRecordRequest request;
  request.WithStreamName(FLAGS_aws_kinesis_stream)
      .WithPartitionKey(shardId_)
      .WithData(Aws::Utils::ByteBuffer((unsigned char*)s.c_str(), s.length()));

  Aws::Kinesis::Model::PutRecordOutcome outcome = client_.PutRecord(request);
  if (outcome.IsSuccess()) {
    return Status(0, "OK");
  } else {
    VLOG(1) << "Failed with error " << outcome.GetError().GetMessage();
    return Status(1, outcome.GetError().GetMessage());
  }

  return Status(0, "OK");
}

}

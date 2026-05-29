package cloudwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"golang.org/x/sync/errgroup"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

const (
	defaultEventLimit           = int32(10)
	defaultLogGroupLimit        = int32(50)
	logIdentifierInternal       = "__log__grafana_internal__"
	logStreamIdentifierInternal = "__logstream__grafana_internal__"
	logGroupsMacro              = "$__logGroups"

	logContextFieldsClause = "fields @timestamp,ltrim(@log) as " + logIdentifierInternal + ",ltrim(@logStream) as " + logStreamIdentifierInternal

	maxSourceLogGroupPrefixes   = 5
	minSourceLogGroupPrefixLen  = 3
	maxSourceAccountIdentifiers = 20
)

var sourceCommandRegex = regexp.MustCompile(`(?i)^\s*source\s+`)

type AWSError struct {
	Code    string
	Message string
	Payload map[string]string
}

func (e *AWSError) Error() string {
	return fmt.Sprintf("CloudWatch error: %s: %s", e.Code, e.Message)
}

func (ds *DataSource) executeLogActions(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	resp := backend.NewQueryDataResponse()

	resultChan := make(chan backend.Responses, len(req.Queries))
	eg, ectx := errgroup.WithContext(ctx)

	for _, query := range req.Queries {
		var logsQuery models.LogsQuery
		err := json.Unmarshal(query.JSON, &logsQuery)
		if err != nil {
			return nil, err
		}

		query := query
		eg.Go(func() error {
			dataframe, err := ds.executeLogAction(ectx, logsQuery, query)
			if err != nil {
				resultChan <- backend.Responses{
					query.RefID: backend.ErrorResponseWithErrorSource(err),
				}
				return nil
			}

			if dataframe == nil {
				resultChan <- backend.Responses{
					query.RefID: backend.DataResponse{Frames: data.Frames{}},
				}
				return nil
			}

			groupedFrames, err := groupResponseFrame(dataframe, logsQuery.StatsGroups)
			if err != nil {
				return err
			}
			resultChan <- backend.Responses{
				query.RefID: backend.DataResponse{Frames: groupedFrames},
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	close(resultChan)

	for result := range resultChan {
		for refID, response := range result {
			respD := resp.Responses[refID]
			respD.Frames = response.Frames
			respD.Error = response.Error
			respD.ErrorSource = response.ErrorSource
			resp.Responses[refID] = respD
		}
	}

	return resp, nil
}

func (ds *DataSource) executeLogAction(ctx context.Context, logsQuery models.LogsQuery, query backend.DataQuery) (*data.Frame, error) {
	region := ds.Settings.Region
	if logsQuery.Region != "" {
		region = logsQuery.Region
	}

	logsClient, err := ds.getCWLogsClient(ctx, region)
	if err != nil {
		return nil, err
	}

	var frame *data.Frame
	switch logsQuery.Subtype {
	case "StartQuery":
		frame, err = ds.handleStartQuery(ctx, logsClient, logsQuery, query.TimeRange, query.RefID)
	case "StopQuery":
		frame, err = ds.handleStopQuery(ctx, logsClient, logsQuery)
	case "GetQueryResults":
		frame, err = ds.handleGetQueryResults(ctx, logsClient, logsQuery, query.RefID)
	case "GetLogEvents":
		frame, err = ds.handleGetLogEvents(ctx, logsClient, logsQuery)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to execute log action with subtype: %s: %w", logsQuery.Subtype, err)
	}

	return frame, nil
}

func groupResponseFrame(frame *data.Frame, statsGroups []string) (data.Frames, error) {
	if frame == nil {
		return data.Frames{}, nil
	}

	var dataFrames data.Frames

	if hasTimeField(frame) {
		if len(statsGroups) > 0 && len(frame.Fields) > 0 {
			groupedFrames, err := groupResults(frame, statsGroups, false)
			if err != nil {
				return nil, err
			}

			dataFrames = groupedFrames
		} else {
			setPreferredVisType(frame, "logs")
			dataFrames = data.Frames{frame}
		}
	} else {
		dataFrames = data.Frames{frame}
	}
	return dataFrames, nil
}

func setPreferredVisType(frame *data.Frame, visType data.VisType) {
	if frame.Meta != nil {
		frame.Meta.PreferredVisualization = visType
	} else {
		frame.Meta = &data.FrameMeta{
			PreferredVisualization: visType,
		}
	}
}

func hasTimeField(frame *data.Frame) bool {
	for _, field := range frame.Fields {
		if field.Type() == data.FieldTypeNullableTime {
			return true
		}
	}
	return false
}

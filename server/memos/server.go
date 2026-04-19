package memos

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/mudkipme/mortis/api"
	v1pb "github.com/mudkipme/mortis/server/memos/proto/gen/api/v1"
	"github.com/mudkipme/mortis/utils"
)

type Server struct {
	baseURL    string
	httpClient *http.Client
	addr       string

	memoIdToName     *xsync.MapOf[int, string]
	resourceIdToName *xsync.MapOf[int, string]
	userIdToName     *xsync.MapOf[int, string]
	userNameToLabel  *xsync.MapOf[string, string]
}

// CreateMemo implements api.ServerInterface.
func (s *Server) CreateMemo(ctx echo.Context) error {
	// parse body to api.CreateMemoParams
	var params api.CreateMemoJSONRequestBody
	if err := ctx.Bind(&params); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to bind request body", "error", err)
		return err
	}

	req := &v1pb.CreateMemoRequest{
		Memo: &v1pb.Memo{
			Visibility: v1pb.Visibility_PRIVATE,
		},
	}
	if params.Content != nil {
		req.Memo.Content = *params.Content
	}
	if params.Visibility != nil {
		switch *params.Visibility {
		case api.Public:
			req.Memo.Visibility = v1pb.Visibility_PUBLIC
		case api.Protected:
			req.Memo.Visibility = v1pb.Visibility_PROTECTED
		case api.Private:
			req.Memo.Visibility = v1pb.Visibility_PRIVATE
		}
	}
	if params.CreatedTs != nil && *params.CreatedTs != 0 {
		req.Memo.CreateTime = timestamppb.New(time.Unix(int64(*params.CreatedTs), 0))
	}
	if params.ResourceIdList != nil {
		for _, resourceId := range *params.ResourceIdList {
			name, err := s.searchResourceId(ctx, resourceId)
			if err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to search resource id", "error", err)
				return err
			}
			req.Memo.Attachments = append(req.Memo.Attachments, &v1pb.Attachment{
				Name: name,
			})
		}
	}
	if params.RelationList != nil {
		for _, relation := range *params.RelationList {
			if relation.RelatedMemoId == nil {
				continue
			}
			relatedName, err := s.searchMemoId(ctx, *relation.RelatedMemoId)
			if err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to search related memo id", "error", err)
				return err
			}
			var relationType v1pb.MemoRelation_Type
			switch *relation.Type {
			case api.MemoRelationComment:
				relationType = v1pb.MemoRelation_COMMENT
			case api.MemoRelationReference:
				relationType = v1pb.MemoRelation_REFERENCE
			}
			req.Memo.Relations = append(req.Memo.Relations, &v1pb.MemoRelation{
				RelatedMemo: &v1pb.MemoRelation_Memo{
					Name: relatedName,
				},
				Type: relationType,
			})
		}
	}

	resp := &v1pb.Memo{}
	if err := s.doProtoRequest(ctx, http.MethodPost, "/api/v1/memos", nil, req.Memo, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to create memo", "error", err)
		return err
	}

	// Convert the response to the API response
	memo := s.convertMemo(resp)
	return ctx.JSON(200, memo)
}

// CreateTag implements api.ServerInterface.
func (s *Server) CreateTag(ctx echo.Context) error {
	var params api.CreateTagJSONRequestBody
	if err := ctx.Bind(&params); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to bind request body", "error", err)
		return err
	}

	return ctx.JSON(200, params.Name)
}

// DeleteMemo implements api.ServerInterface.
func (s *Server) DeleteMemo(ctx echo.Context, memoId int) error {
	name, err := s.searchMemoId(ctx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}
	if err := s.doProtoRequest(ctx, http.MethodDelete, "/api/v1/"+name, nil, nil, nil); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to delete memo", "error", err)
		return err
	}
	return ctx.JSON(200, true)
}

// DeleteResource implements api.ServerInterface.
func (s *Server) DeleteResource(ctx echo.Context, resourceId int) error {
	name, err := s.searchResourceId(ctx, resourceId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search resource id", "error", err)
		return err
	}
	if err := s.doProtoRequest(ctx, http.MethodDelete, "/api/v1/"+name, nil, nil, nil); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to delete resource", "error", err)
		return err
	}
	return ctx.JSON(200, true)
}

// DeleteTag implements api.ServerInterface.
func (s *Server) DeleteTag(ctx echo.Context) error {
	// grpcCtx := s.prepareGrpcContext(ctx)
	// var params api.DeleteTagJSONRequestBody
	// if err := ctx.Bind(&params); err != nil {
	// 	slog.ErrorContext(ctx.Request().Context(), "failed to bind request body", "error", err)
	// 	return err
	// }
	// if params.Name == nil {
	// 	return ctx.JSON(200, false)
	// }

	// _, err := s.memoService.DeleteMemoTag(grpcCtx, &v1pb.DeleteMemoTagRequest{
	// 	Parent: "memos/-",
	// 	Tag:    *params.Name,
	// })
	// if err != nil {
	// 	slog.ErrorContext(ctx.Request().Context(), "failed to delete tag", "error", err)
	// 	return err
	// }
	return ctx.JSON(200, true)
}

// GetCurrentUser implements api.ServerInterface.
func (s *Server) GetCurrentUser(ctx echo.Context) error {
	resp := &v1pb.GetCurrentUserResponse{}
	if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/auth/me", nil, nil, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get current user", "error", err)
		return err
	}
	if resp.GetUser() == nil {
		slog.ErrorContext(ctx.Request().Context(), "current user not found")
		return echo.NewHTTPError(http.StatusUnauthorized, "current user not found")
	}
	rowStatus := api.Normal
	if resp.User.State == v1pb.State_ARCHIVED {
		rowStatus = api.Archived
	}
	var role api.Role
	switch resp.User.Role {
	case v1pb.User_ADMIN:
		role = api.RoleAdmin
	case v1pb.User_USER:
		role = api.RoleUser
	}
	userID := s.cacheUserName(resp.User.Name)
	return ctx.JSON(200, &api.User{
		Id:        userID,
		AvatarUrl: &resp.User.AvatarUrl,
		CreatedTs: utils.IntPtr(int(resp.User.CreateTime.AsTime().Unix())),
		Email:     &resp.User.Email,
		Username:  &resp.User.Username,
		Nickname:  &resp.User.DisplayName,
		RowStatus: &rowStatus,
		UpdatedTs: utils.IntPtr(int(resp.User.UpdateTime.AsTime().Unix())),
		Role:      &role,
	})
}

// GetMemo implements api.ServerInterface.
func (s *Server) GetMemo(ctx echo.Context, memoId int) error {
	name, err := s.searchMemoId(ctx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}

	resp := &v1pb.Memo{}
	if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/"+name, nil, nil, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get memo", "error", err)
		return err
	}
	memo := s.convertMemo(resp)
	return ctx.JSON(200, memo)
}

// GetMemoRelations implements api.ServerInterface.
func (s *Server) GetMemoRelations(ctx echo.Context, memoId int) error {
	name, err := s.searchMemoId(ctx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}
	resp := &v1pb.Memo{}
	if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/"+name, nil, nil, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get memo", "error", err)
		return err
	}

	var relations []*api.MemoRelation
	for _, relation := range resp.Relations {
		relatedMemoID := int(hashToInt53(strings.TrimPrefix(relation.RelatedMemo.GetName(), "memos/")))
		var relationType api.MemoRelationType
		switch relation.Type {
		case v1pb.MemoRelation_COMMENT:
			relationType = api.MemoRelationComment
		case v1pb.MemoRelation_REFERENCE:
			relationType = api.MemoRelationReference
		}

		relations = append(relations, &api.MemoRelation{
			MemoID:        &memoId,
			RelatedMemoID: &relatedMemoID,
			Type:          &relationType,
		})
	}
	return ctx.JSON(200, relations)
}

// GetStatus implements api.ServerInterface.
func (s *Server) GetStatus(ctx echo.Context) error {
	resp := &v1pb.InstanceProfile{}
	if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/instance/profile", nil, nil, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get workspace profile", "error", err)
		return err
	}

	mode := "prod"
	if resp.Demo {
		mode = "demo"
	}

	return ctx.JSON(200, &api.SystemStatus{
		Profile: &api.Profile{
			Mode:    &mode,
			Version: &resp.Version,
		},
	})
}

// ListMemos implements api.ServerInterface.
func (s *Server) ListMemos(ctx echo.Context, params api.ListMemosParams) error {
	filter := ""
	if params.CreatorId != nil {
		name, err := s.searchUserId(ctx, *params.CreatorId)
		if err != nil {
			slog.ErrorContext(ctx.Request().Context(), "failed to search user id", "creatorId", *params.CreatorId, "error", err)
			return err
		}
		filter = s.memoCreatorFilter(name)
	} else {
		user := &v1pb.GetCurrentUserResponse{}
		if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/auth/me", nil, nil, user); err != nil {
			slog.ErrorContext(ctx.Request().Context(), "failed to get current user", "error", err)
			return err
		}
		if user.GetUser() != nil {
			filter = s.memoCreatorFilter(user.GetUser().GetName())
		}
	}

	state := v1pb.State_STATE_UNSPECIFIED
	if params.RowStatus != nil && *params.RowStatus == api.ARCHIVED {
		state = v1pb.State_ARCHIVED
	}

	var allResp []*v1pb.Memo
	if params.Limit == nil && params.Offset == nil {
		pageToken := ""
		for {
			query := url.Values{}
			query.Set("pageSize", "200")
			if pageToken != "" {
				query.Set("pageToken", pageToken)
			}
			if filter != "" {
				query.Set("filter", filter)
			}
			if state != v1pb.State_STATE_UNSPECIFIED {
				query.Set("state", state.String())
			}
			resp := &v1pb.ListMemosResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/memos", query, nil, resp); err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to list memos", "error", err)
				return err
			}
			allResp = append(allResp, resp.Memos...)
			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}
	} else {
		limit := 10
		if params.Limit != nil && *params.Limit > 0 {
			limit = *params.Limit
		}
		offset := 0
		if params.Offset != nil {
			offset = *params.Offset
		}
		pageToken := ""
		remainingOffset := offset
		for len(allResp) < limit {
			pageSize := int32(limit)
			if remainingOffset > 0 {
				pageSize = int32(remainingOffset + limit)
				if pageSize > 1000 {
					pageSize = 1000
				}
			}
			query := url.Values{}
			query.Set("pageSize", fmt.Sprintf("%d", pageSize))
			if pageToken != "" {
				query.Set("pageToken", pageToken)
			}
			if filter != "" {
				query.Set("filter", filter)
			}
			if state != v1pb.State_STATE_UNSPECIFIED {
				query.Set("state", state.String())
			}
			resp := &v1pb.ListMemosResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/memos", query, nil, resp); err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to list memos", "error", err)
				return err
			}
			if len(resp.Memos) == 0 {
				break
			}
			start := 0
			if remainingOffset > 0 {
				if remainingOffset >= len(resp.Memos) {
					remainingOffset -= len(resp.Memos)
					start = len(resp.Memos)
				} else {
					start = remainingOffset
					remainingOffset = 0
				}
			}
			for _, memo := range resp.Memos[start:] {
				allResp = append(allResp, memo)
				if len(allResp) >= limit {
					break
				}
			}
			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}
	}

	memos := []*api.Memo{}
	for _, memo := range allResp {
		m := s.convertMemo(memo)
		memos = append(memos, m)
	}

	// Convert the response to the API response
	return ctx.JSON(200, memos)
}

// ListPublicMemos implements api.ServerInterface.
func (s *Server) ListPublicMemos(ctx echo.Context, params api.ListPublicMemosParams) error {
	filter := "visibility in [\"PUBLIC\", \"PROTECTED\"]"
	var allResp []*v1pb.Memo
	if params.Limit == nil && params.Offset == nil {
		pageToken := ""
		for {
			query := url.Values{}
			query.Set("pageSize", "200")
			query.Set("filter", filter)
			if pageToken != "" {
				query.Set("pageToken", pageToken)
			}
			resp := &v1pb.ListMemosResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/memos", query, nil, resp); err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to list memos", "error", err)
				return err
			}
			allResp = append(allResp, resp.Memos...)
			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}
	} else {
		limit := 10
		if params.Limit != nil && *params.Limit > 0 {
			limit = *params.Limit
		}
		offset := 0
		if params.Offset != nil {
			offset = *params.Offset
		}
		pageToken := ""
		remainingOffset := offset
		for len(allResp) < limit {
			pageSize := int32(limit)
			if remainingOffset > 0 {
				pageSize = int32(remainingOffset + limit)
				if pageSize > 1000 {
					pageSize = 1000
				}
			}
			query := url.Values{}
			query.Set("pageSize", fmt.Sprintf("%d", pageSize))
			query.Set("filter", filter)
			if pageToken != "" {
				query.Set("pageToken", pageToken)
			}
			resp := &v1pb.ListMemosResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/memos", query, nil, resp); err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to list memos", "error", err)
				return err
			}
			if len(resp.Memos) == 0 {
				break
			}
			start := 0
			if remainingOffset > 0 {
				if remainingOffset >= len(resp.Memos) {
					remainingOffset -= len(resp.Memos)
					start = len(resp.Memos)
				} else {
					start = remainingOffset
					remainingOffset = 0
				}
			}
			for _, memo := range resp.Memos[start:] {
				allResp = append(allResp, memo)
				if len(allResp) >= limit {
					break
				}
			}
			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}
	}

	memos := make([]*api.Memo, 0, len(allResp))
	for _, memo := range allResp {
		memos = append(memos, s.convertMemo(memo))
	}
	s.populateMemoCreatorNames(ctx, allResp, memos)

	// Convert the response to the API response
	return ctx.JSON(200, memos)
}

// ListResources implements api.ServerInterface.
func (s *Server) ListResources(ctx echo.Context, params api.ListResourcesParams) error {
	var allResp []*v1pb.Attachment
	if params.Limit == nil && params.Offset == nil {
		pageToken := ""
		for {
			query := url.Values{}
			query.Set("pageSize", "200")
			if pageToken != "" {
				query.Set("pageToken", pageToken)
			}
			resp := &v1pb.ListAttachmentsResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/attachments", query, nil, resp); err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to list resources", "error", err)
				return err
			}
			allResp = append(allResp, resp.Attachments...)
			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}
	} else {
		limit := 10
		if params.Limit != nil && *params.Limit > 0 {
			limit = *params.Limit
		}
		offset := 0
		if params.Offset != nil {
			offset = *params.Offset
		}
		pageToken := ""
		remainingOffset := offset
		for len(allResp) < limit {
			pageSize := int32(limit)
			if remainingOffset > 0 {
				pageSize = int32(remainingOffset + limit)
				if pageSize > 1000 {
					pageSize = 1000
				}
			}
			query := url.Values{}
			query.Set("pageSize", fmt.Sprintf("%d", pageSize))
			if pageToken != "" {
				query.Set("pageToken", pageToken)
			}
			resp := &v1pb.ListAttachmentsResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/attachments", query, nil, resp); err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to list resources", "error", err)
				return err
			}
			if len(resp.Attachments) == 0 {
				break
			}
			start := 0
			if remainingOffset > 0 {
				if remainingOffset >= len(resp.Attachments) {
					remainingOffset -= len(resp.Attachments)
					start = len(resp.Attachments)
				} else {
					start = remainingOffset
					remainingOffset = 0
				}
			}
			for _, resource := range resp.Attachments[start:] {
				allResp = append(allResp, resource)
				if len(allResp) >= limit {
					break
				}
			}
			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}
	}

	resources := []*api.Resource{}
	for _, resource := range allResp {
		resources = append(resources, s.convertResource(resource))
	}
	return ctx.JSON(200, resources)
}

// ListTags implements api.ServerInterface.
func (s *Server) ListTags(ctx echo.Context) error {
	user := &v1pb.GetCurrentUserResponse{}
	if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/auth/me", nil, nil, user); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get current user", "error", err)
		return err
	}
	if user.GetUser() == nil {
		return ctx.JSON(200, []string{})
	}
	resp := &v1pb.UserStats{}
	if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/"+user.GetUser().GetName()+":getStats", nil, nil, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get user stats", "error", err)
		return err
	}

	tags := []string{}
	for tag := range resp.TagCount {
		tags = append(tags, tag)
	}
	return ctx.JSON(200, tags)
}

// OrganizeMemo implements api.ServerInterface.
func (s *Server) OrganizeMemo(ctx echo.Context, memoId int) error {
	var params api.OrganizeMemoJSONRequestBody
	if err := ctx.Bind(&params); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to bind request body", "error", err)
		return err
	}

	name, err := s.searchMemoId(ctx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}
	query := url.Values{}
	query.Set("updateMask", "pinned")
	resp := &v1pb.Memo{}
	if err := s.doProtoRequest(ctx, http.MethodPatch, "/api/v1/"+name, query, &v1pb.Memo{
		Name:   name,
		Pinned: params.Pinned != nil && *params.Pinned,
	}, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to organize memo", "error", err)
		return err
	}
	// Convert the response to the API response
	memo := s.convertMemo(resp)
	return ctx.JSON(200, memo)
}

// UpdateMemo implements api.ServerInterface.
func (s *Server) UpdateMemo(ctx echo.Context, memoId int) error {
	var params api.UpdateMemoJSONRequestBody
	if err := ctx.Bind(&params); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to bind request body", "error", err)
		return err
	}

	name, err := s.searchMemoId(ctx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}

	req := &v1pb.UpdateMemoRequest{
		UpdateMask: &fieldmaskpb.FieldMask{},
		Memo: &v1pb.Memo{
			Name: name,
		},
	}
	if params.Content != nil {
		req.Memo.Content = *params.Content
		req.UpdateMask.Paths = append(req.UpdateMask.Paths, "content")
	}
	if params.Visibility != nil {
		switch *params.Visibility {
		case api.Public:
			req.Memo.Visibility = v1pb.Visibility_PUBLIC
		case api.Protected:
			req.Memo.Visibility = v1pb.Visibility_PROTECTED
		case api.Private:
			req.Memo.Visibility = v1pb.Visibility_PRIVATE
		}
		req.UpdateMask.Paths = append(req.UpdateMask.Paths, "visibility")
	}
	if params.ResourceIdList != nil {
		req.Memo.Attachments = []*v1pb.Attachment{}
		for _, resourceId := range *params.ResourceIdList {
			name, err := s.searchResourceId(ctx, resourceId)
			if err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to search resource id", "error", err)
				return err
			}
			req.Memo.Attachments = append(req.Memo.Attachments, &v1pb.Attachment{
				Name: name,
			})
			req.UpdateMask.Paths = append(req.UpdateMask.Paths, "attachments")
		}
	}
	if params.RowStatus != nil {
		switch *params.RowStatus {
		case api.Normal:
			req.Memo.State = v1pb.State_NORMAL
		case api.Archived:
			req.Memo.State = v1pb.State_ARCHIVED
		}
		req.UpdateMask.Paths = append(req.UpdateMask.Paths, "state")
	}
	if params.CreatedTs != nil && *params.CreatedTs != 0 {
		req.Memo.CreateTime = timestamppb.New(time.Unix(int64(*params.CreatedTs), 0))
		req.UpdateMask.Paths = append(req.UpdateMask.Paths, "create_time")
	}
	if params.UpdatedTs != nil && *params.UpdatedTs != 0 {
		req.Memo.UpdateTime = timestamppb.New(time.Unix(int64(*params.UpdatedTs), 0))
		req.UpdateMask.Paths = append(req.UpdateMask.Paths, "update_time")
	}
	if params.RelationList != nil {
		req.Memo.Relations = []*v1pb.MemoRelation{}
		for _, relation := range *params.RelationList {
			if relation.RelatedMemoId == nil {
				continue
			}
			relatedName, err := s.searchMemoId(ctx, *relation.RelatedMemoId)
			if err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to search related memo id", "error", err)
				return err
			}
			var relationType v1pb.MemoRelation_Type
			switch *relation.Type {
			case api.MemoRelationComment:
				relationType = v1pb.MemoRelation_COMMENT
			case api.MemoRelationReference:
				relationType = v1pb.MemoRelation_REFERENCE
			}
			req.Memo.Relations = append(req.Memo.Relations, &v1pb.MemoRelation{
				RelatedMemo: &v1pb.MemoRelation_Memo{
					Name: relatedName,
				},
				Type: relationType,
			})
		}
		req.UpdateMask.Paths = append(req.UpdateMask.Paths, "relations")
	}

	query := url.Values{}
	if len(req.UpdateMask.Paths) > 0 {
		query.Set("updateMask", strings.Join(req.UpdateMask.Paths, ","))
	}
	resp := &v1pb.Memo{}
	if err := s.doProtoRequest(ctx, http.MethodPatch, "/api/v1/"+name, query, req.Memo, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to update memo", "error", err)
		return err
	}
	// Convert the response to the API response
	memo := s.convertMemo(resp)
	return ctx.JSON(200, memo)
}

// UpdateResource implements api.ServerInterface.
func (s *Server) UpdateResource(ctx echo.Context, resourceId int) error {
	var params api.UpdateResourceRequest
	if err := ctx.Bind(&params); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to bind request body", "error", err)
		return err
	}

	name, err := s.searchResourceId(ctx, resourceId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search resource id", "error", err)
		return err
	}
	req := &v1pb.UpdateAttachmentRequest{
		Attachment: &v1pb.Attachment{
			Name: name,
		},
		UpdateMask: &fieldmaskpb.FieldMask{},
	}
	if params.Filename != nil {
		req.Attachment.Filename = *params.Filename
		req.UpdateMask.Paths = append(req.UpdateMask.Paths, "filename")
	}

	query := url.Values{}
	if len(req.UpdateMask.Paths) > 0 {
		query.Set("updateMask", strings.Join(req.UpdateMask.Paths, ","))
	}
	resp := &v1pb.Attachment{}
	if err := s.doProtoRequest(ctx, http.MethodPatch, "/api/v1/"+name, query, req.Attachment, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to update resource", "error", err)
		return err
	}
	resource := s.convertResource(resp)
	return ctx.JSON(200, resource)
}

// UploadResource implements api.ServerInterface.
func (s *Server) UploadResource(ctx echo.Context) error {
	file, err := ctx.FormFile("file")
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get form file", "error", err)
		return err
	}
	src, err := file.Open()
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to open form file", "error", err)
		return err
	}
	defer src.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, src)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to read form file", "error", err)
		return err
	}

	// Get the mime type of the file
	mimeType := file.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = http.DetectContentType(buf.Bytes())
	}

	resp := &v1pb.Attachment{}
	if err := s.doProtoRequest(ctx, http.MethodPost, "/api/v1/attachments", nil, &v1pb.Attachment{
		Filename: file.Filename,
		Type:     mimeType,
		Content:  buf.Bytes(),
	}, resp); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to create resource", "error", err)
		return err
	}

	resource := s.convertResource(resp)
	return ctx.JSON(200, resource)
}

func (s *Server) StreamResource(ctx echo.Context) error {
	uid := ctx.Param("uid")
	filename := ctx.Param("filename")
	if filename == "" {
		filename = "file"
	}

	thumbnailParam := ctx.QueryParam("thumbnail")
	thumbnail := thumbnailParam == "1" || strings.EqualFold(thumbnailParam, "true")

	endpoint := fmt.Sprintf("%s/file/attachments/%s/%s", s.baseURL, url.PathEscape(uid), url.PathEscape(filename))
	if thumbnail {
		endpoint = endpoint + "?thumbnail=true"
	}

	req, err := http.NewRequestWithContext(ctx.Request().Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to create attachment request", "error", err)
		return err
	}
	if authHeader := ctx.Request().Header.Get("Authorization"); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to fetch resource binary", "error", err)
		return err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		ctx.Response().Header().Set("Content-Type", contentType)
	}
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		ctx.Response().Header().Set("Content-Length", contentLength)
	}

	ctx.Response().WriteHeader(resp.StatusCode)
	_, err = io.Copy(ctx.Response().Writer, resp.Body)
	return err
}

func NewServer(serverAddr string) *Server {
	baseURL := serverAddr
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		baseURL = "http://" + serverAddr
	}

	return &Server{
		baseURL:          strings.TrimRight(baseURL, "/"),
		httpClient:       http.DefaultClient,
		addr:             serverAddr,
		memoIdToName:     xsync.NewMapOf[int, string](),
		resourceIdToName: xsync.NewMapOf[int, string](),
		userIdToName:     xsync.NewMapOf[int, string](),
		userNameToLabel:  xsync.NewMapOf[string, string](),
	}
}

func (s *Server) buildURL(path string, query url.Values) string {
	endpoint := s.baseURL + path
	if len(query) > 0 {
		endpoint = endpoint + "?" + query.Encode()
	}
	return endpoint
}

func (s *Server) doProtoRequest(ctx echo.Context, method, path string, query url.Values, req proto.Message, resp proto.Message) error {
	endpoint := s.buildURL(path, query)

	var body io.Reader
	if req != nil {
		payload, err := protojson.MarshalOptions{EmitUnpopulated: false}.Marshal(req)
		if err != nil {
			return errors.Wrap(err, "failed to marshal request")
		}
		body = bytes.NewReader(payload)
	}

	reqHTTP, err := http.NewRequestWithContext(ctx.Request().Context(), method, endpoint, body)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	if req != nil {
		reqHTTP.Header.Set("Content-Type", "application/json")
	}
	if authHeader := ctx.Request().Header.Get("Authorization"); authHeader != "" {
		reqHTTP.Header.Set("Authorization", authHeader)
	}
	if cookieHeader := ctx.Request().Header.Get("Cookie"); cookieHeader != "" {
		reqHTTP.Header.Set("Cookie", cookieHeader)
	}

	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	respHTTP, err := client.Do(reqHTTP)
	if err != nil {
		return errors.Wrap(err, "request failed")
	}
	defer respHTTP.Body.Close()

	data, err := io.ReadAll(respHTTP.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read response")
	}
	if respHTTP.StatusCode < http.StatusOK || respHTTP.StatusCode >= http.StatusBadRequest {
		return echo.NewHTTPError(respHTTP.StatusCode, strings.TrimSpace(string(data)))
	}
	if resp == nil || len(data) == 0 {
		return nil
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, resp); err != nil {
		return errors.Wrap(err, "failed to unmarshal response")
	}
	return nil
}

func (s *Server) convertResource(resource *v1pb.Attachment) *api.Resource {
	id := int(hashToInt53(strings.TrimPrefix(resource.Name, "attachments/")))
	s.resourceIdToName.Store(id, resource.Name)
	return &api.Resource{
		Id:           id,
		CreatedTs:    utils.IntPtr(int(resource.CreateTime.AsTime().Unix())),
		CreatorId:    utils.IntPtr(0),
		ExternalLink: utils.StringPtr(resource.ExternalLink),
		Filename:     resource.Filename,
		Name:         utils.StringPtr(resource.Name),
		Size:         utils.IntPtr(int(resource.Size)),
		Type:         utils.StringPtr(resource.Type),
		Uid:          utils.StringPtr(strings.TrimPrefix(resource.Name, "attachments/")),
		UpdatedTs:    utils.IntPtr(int(resource.CreateTime.AsTime().Unix())),
	}
}

func (s *Server) convertMemo(memo *v1pb.Memo) *api.Memo {
	rowStatus := api.Normal
	if memo.State == v1pb.State_ARCHIVED {
		rowStatus = api.Archived
	}
	visibility := api.Private
	switch memo.Visibility {
	case v1pb.Visibility_PUBLIC:
		visibility = api.Public
	case v1pb.Visibility_PROTECTED:
		visibility = api.Protected
	}

	resources := []api.Resource{}
	for _, resource := range memo.Attachments {
		resources = append(resources, *s.convertResource(resource))
	}

	id := int(hashToInt53(strings.TrimPrefix(memo.Name, "memos/")))
	s.memoIdToName.Store(id, memo.Name)
	var creatorID *int
	if memo.Creator != "" {
		creatorID = utils.IntPtr(s.cacheUserName(memo.Creator))
	}
	return &api.Memo{
		Id:           id,
		Content:      memo.Content,
		CreatedTs:    int(memo.CreateTime.AsTime().Unix()),
		CreatorId:    creatorID,
		Pinned:       utils.BoolPtr(memo.Pinned),
		RowStatus:    &rowStatus,
		UpdatedTs:    utils.IntPtr(int(memo.UpdateTime.AsTime().Unix())),
		Visibility:   &visibility,
		ResourceList: &resources,
	}
}

func (s *Server) populateMemoCreatorNames(ctx echo.Context, sourceMemos []*v1pb.Memo, apiMemos []*api.Memo) {
	creatorNames := make(map[string]string)
	missingCreators := make([]string, 0)
	seenMissing := make(map[string]struct{})

	for _, memo := range sourceMemos {
		if memo == nil || memo.Creator == "" {
			continue
		}
		s.cacheUserName(memo.Creator)
		if cached, ok := s.userNameToLabel.Load(memo.Creator); ok && cached != "" {
			creatorNames[memo.Creator] = cached
			continue
		}
		if _, ok := seenMissing[memo.Creator]; ok {
			continue
		}
		seenMissing[memo.Creator] = struct{}{}
		missingCreators = append(missingCreators, memo.Creator)
	}

	for _, creator := range missingCreators {
		resp := &v1pb.User{}
		if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/"+creator, nil, nil, resp); err != nil {
			slog.WarnContext(ctx.Request().Context(), "failed to get memo creator", "creator", creator, "error", err)
			continue
		}
		name := resp.GetDisplayName()
		if name == "" {
			name = resp.GetUsername()
		}
		if name == "" {
			continue
		}
		creatorNames[creator] = name
		s.cacheUserName(creator)
		s.userNameToLabel.Store(creator, name)
	}

	for i, memo := range sourceMemos {
		if i >= len(apiMemos) || memo == nil {
			continue
		}
		if name, ok := creatorNames[memo.Creator]; ok && name != "" {
			apiMemos[i].CreatorName = utils.StringPtr(name)
		}
	}
}

func (s *Server) memoCreatorFilter(name string) string {
	if name == "" {
		return ""
	}
	if numericID, err := strconv.Atoi(strings.TrimPrefix(name, "users/")); err == nil {
		return fmt.Sprintf("creator_id == %d", numericID)
	}
	return fmt.Sprintf("creator == %q", name)
}

func (s *Server) cacheUserName(name string) int {
	if name == "" {
		return 0
	}
	userID := legacyUserID(name)
	s.userIdToName.Store(userID, name)
	return userID
}

func legacyUserID(name string) int {
	token := strings.TrimPrefix(name, "users/")
	if parsed, err := strconv.Atoi(token); err == nil {
		return parsed
	}
	return int(hashToInt53(token))
}

func (s *Server) searchUserId(ctx echo.Context, userId int) (string, error) {
	name, ok := s.userIdToName.Load(userId)
	if !ok {
		currentPageToken := ""
		for {
			query := url.Values{}
			query.Set("pageSize", "200")
			if currentPageToken != "" {
				query.Set("pageToken", currentPageToken)
			}
			resp := &v1pb.ListUsersResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/users", query, nil, resp); err != nil {
				return "", errors.Wrap(err, "failed to list users")
			}
			for _, user := range resp.Users {
				candidate := s.cacheUserName(user.GetName())
				if candidate == userId {
					name = user.GetName()
				}
			}
			if name != "" || resp.NextPageToken == "" {
				break
			}
			currentPageToken = resp.NextPageToken
		}
	}
	if name == "" {
		return "", errors.New("user not found")
	}
	return name, nil
}

func (s *Server) searchMemoId(ctx echo.Context, memoId int) (string, error) {
	name, ok := s.memoIdToName.Load(memoId)
	if !ok {
		var currentPageToken string
		for {
			query := url.Values{}
			query.Set("pageSize", "200")
			if currentPageToken != "" {
				query.Set("pageToken", currentPageToken)
			}
			resp := &v1pb.ListMemosResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/memos", query, nil, resp); err != nil {
				return "", errors.Wrapf(err, "failed to list memos")
			}

			for _, memo := range resp.Memos {
				id := int(hashToInt53(strings.TrimPrefix(memo.Name, "memos/")))
				s.memoIdToName.Store(id, memo.Name)
				if id == memoId {
					name = memo.Name
					break
				}
			}

			if name != "" || resp.NextPageToken == "" {
				break
			}

			currentPageToken = resp.NextPageToken
		}
	}

	if name == "" {
		return "", errors.New("memo not found")
	}

	return name, nil
}

func (s *Server) searchResourceId(ctx echo.Context, resourceId int) (string, error) {
	name, ok := s.resourceIdToName.Load(resourceId)
	if !ok {
		currentPageToken := ""
		for {
			query := url.Values{}
			query.Set("pageSize", "200")
			if currentPageToken != "" {
				query.Set("pageToken", currentPageToken)
			}
			resp := &v1pb.ListAttachmentsResponse{}
			if err := s.doProtoRequest(ctx, http.MethodGet, "/api/v1/attachments", query, nil, resp); err != nil {
				return "", errors.Wrapf(err, "failed to list resources")
			}
			for _, resource := range resp.Attachments {
				id := int(hashToInt53(strings.TrimPrefix(resource.Name, "attachments/")))
				s.resourceIdToName.Store(id, resource.Name)
				if id == resourceId {
					name = resource.Name
					break
				}
			}
			if name != "" || resp.NextPageToken == "" {
				break
			}
			currentPageToken = resp.NextPageToken
		}
	}
	if name == "" {
		return "", errors.New("resource not found")
	}
	return name, nil
}

// hashToInt53 hashes a string to a 53-bit integer.
func hashToInt53(s string) int64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	hash := h.Sum64()

	// Mask to get only the lower 53 bits
	const mask53 = (1 << 53) - 1
	return int64(hash & mask53)
}

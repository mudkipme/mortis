package memos

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/mudkipme/mortis/api"
	v1pb "github.com/mudkipme/mortis/server/memos/proto/gen/api/v1"
	"github.com/mudkipme/mortis/utils"
)

type Server struct {
	memoService       v1pb.MemoServiceClient
	authService       v1pb.AuthServiceClient
	instanceService   v1pb.InstanceServiceClient
	userService       v1pb.UserServiceClient
	attachmentService v1pb.AttachmentServiceClient

	memoIdToName     *xsync.MapOf[int, string]
	resourceIdToName *xsync.MapOf[int, string]
}

// CreateMemo implements api.ServerInterface.
func (s *Server) CreateMemo(ctx echo.Context) error {
	// parse body to api.CreateMemoParams
	var params api.CreateMemoJSONRequestBody
	if err := ctx.Bind(&params); err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to bind request body", "error", err)
		return err
	}

	// Call the gRPC service
	grpcCtx := s.prepareGrpcContext(ctx)
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
			name, err := s.searchResourceId(grpcCtx, resourceId)
			if err != nil {
				slog.ErrorContext(
					ctx.Request().Context(),
					"failed to search resource id",
					"error",
					err,
				)
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
			relatedName, err := s.searchMemoId(grpcCtx, *relation.RelatedMemoId)
			if err != nil {
				slog.ErrorContext(
					ctx.Request().Context(),
					"failed to search related memo id",
					"error",
					err,
				)
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

	resp, err := s.memoService.CreateMemo(grpcCtx, req)
	if err != nil {
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
	grpcCtx := s.prepareGrpcContext(ctx)
	name, err := s.searchMemoId(grpcCtx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}
	_, err = s.memoService.DeleteMemo(grpcCtx, &v1pb.DeleteMemoRequest{
		Name: name,
	})
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to delete memo", "error", err)
		return err
	}
	return ctx.JSON(200, true)
}

// DeleteResource implements api.ServerInterface.
func (s *Server) DeleteResource(ctx echo.Context, resourceId int) error {
	grpcCtx := s.prepareGrpcContext(ctx)
	name, err := s.searchResourceId(grpcCtx, resourceId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search resource id", "error", err)
		return err
	}
	_, err = s.attachmentService.DeleteAttachment(grpcCtx, &v1pb.DeleteAttachmentRequest{
		Name: name,
	})
	if err != nil {
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
	grpcCtx := s.prepareGrpcContext(ctx)
	resp, err := s.authService.GetCurrentSession(grpcCtx, &v1pb.GetCurrentSessionRequest{})
	if err != nil {
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
	case v1pb.User_HOST:
		role = api.RoleHost
	case v1pb.User_ADMIN:
		role = api.RoleAdmin
	case v1pb.User_USER:
		role = api.RoleUser
	}
	return ctx.JSON(200, &api.User{
		Id:        int(hashToInt53(strings.TrimPrefix(resp.User.Name, "users/"))),
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
	grpcCtx := s.prepareGrpcContext(ctx)
	name, err := s.searchMemoId(grpcCtx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}

	resp, err := s.memoService.GetMemo(grpcCtx, &v1pb.GetMemoRequest{
		Name: name,
	})
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get memo", "error", err)
		return err
	}
	memo := s.convertMemo(resp)
	return ctx.JSON(200, memo)
}

// GetMemoRelations implements api.ServerInterface.
func (s *Server) GetMemoRelations(ctx echo.Context, memoId int) error {
	grpcCtx := s.prepareGrpcContext(ctx)
	name, err := s.searchMemoId(grpcCtx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}
	resp, err := s.memoService.GetMemo(grpcCtx, &v1pb.GetMemoRequest{
		Name: name,
	})
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get memo", "error", err)
		return err
	}

	var relations []*api.MemoRelation
	for _, relation := range resp.Relations {
		relatedMemoID := int(
			hashToInt53(strings.TrimPrefix(relation.RelatedMemo.GetName(), "memos/")),
		)
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
	grpcCtx := s.prepareGrpcContext(ctx)

	resp, err := s.instanceService.GetWorkspaceProfile(grpcCtx, &v1pb.GetWorkspaceProfileRequest{})
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get instance profile", "error", err)
		return err
	}

	return ctx.JSON(200, &api.SystemStatus{
		Profile: &api.Profile{
			Mode:    &resp.Mode,
			Version: &resp.Version,
		},
	})
}

// ListMemos implements api.ServerInterface.
func (s *Server) ListMemos(ctx echo.Context, params api.ListMemosParams) error {
	grpcCtx := s.prepareGrpcContext(ctx)

	req := &v1pb.ListMemosRequest{}
	if params.CreatorId != nil {
		req.Filter = fmt.Sprintf("creator_id == %d", *params.CreatorId)
	} else {
		user, err := s.authService.GetCurrentSession(grpcCtx, &v1pb.GetCurrentSessionRequest{})
		if err != nil {
			slog.ErrorContext(ctx.Request().Context(), "failed to get current user", "error", err)
			return err
		}
		req.Filter = fmt.Sprintf("creator_id == %s", strings.TrimPrefix(user.GetUser().GetName(), "users/"))
	}
	if params.RowStatus != nil && *params.RowStatus == api.ARCHIVED {
		req.State = v1pb.State_ARCHIVED
	}
	var allResp []*v1pb.Memo

	if params.Limit == nil && params.Offset == nil {
		req.PageSize = 200
		for {
			resp, err := s.memoService.ListMemos(grpcCtx, req)
			if err != nil {
				slog.ErrorContext(ctx.Request().Context(), "failed to list memos", "error", err)
				return err
			}
			allResp = append(allResp, resp.Memos...)
			if resp.NextPageToken == "" {
				break
			}
			req.PageToken = resp.NextPageToken
		}
	} else {
		limit := 10
		if params.Limit != nil {
			limit = *params.Limit
		}
		req.PageSize = int32(limit)
		req.PageToken, _ = marshalPageToken(&v1pb.PageToken{Offset: int32(*params.Offset), Limit: int32(limit)})

		// Call the gRPC service
		resp, err := s.memoService.ListMemos(grpcCtx, req)
		if err != nil {
			slog.ErrorContext(ctx.Request().Context(), "failed to list memos", "error", err)
			return err
		}
		allResp = resp.Memos
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
	grpcCtx := s.prepareGrpcContext(ctx)

	req := &v1pb.ListMemosRequest{}
	if params.Limit != nil {
		req.PageSize = int32(*params.Limit)
	}
	if params.Offset != nil {
		limit := 10
		if params.Limit != nil {
			limit = *params.Limit
		}
		req.PageToken, _ = marshalPageToken(
			&v1pb.PageToken{Offset: int32(*params.Offset), Limit: int32(limit)},
		)
	}

	// Call the gRPC service
	resp, err := s.memoService.ListMemos(grpcCtx, req)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to list memos", "error", err)
		return err
	}

	memos := []*api.Memo{}
	for _, memo := range resp.Memos {
		m := s.convertMemo(memo)
		memos = append(memos, m)
	}

	// Convert the response to the API response
	return ctx.JSON(200, memos)
}

// ListResources implements api.ServerInterface.
func (s *Server) ListResources(ctx echo.Context, params api.ListResourcesParams) error {
	grpcCtx := s.prepareGrpcContext(ctx)

	resp, err := s.attachmentService.ListAttachments(grpcCtx, &v1pb.ListAttachmentsRequest{})
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to list resources", "error", err)
		return err
	}

	var resources []*api.Resource
	var offset int
	if params.Offset != nil {
		offset = *params.Offset
	}
	for index, resource := range resp.Attachments {
		if offset > index {
			continue
		}
		if params.Limit != nil && *params.Limit > 0 && *params.Limit+offset <= index {
			break
		}
		resources = append(resources, s.convertResource(resource))
	}
	return ctx.JSON(200, resources)
}

// ListTags implements api.ServerInterface.
func (s *Server) ListTags(ctx echo.Context) error {
	grpcCtx := s.prepareGrpcContext(ctx)

	user, err := s.authService.GetCurrentSession(grpcCtx, &v1pb.GetCurrentSessionRequest{})
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get current user", "error", err)
		return err
	}

	resp, err := s.userService.GetUserStats(grpcCtx, &v1pb.GetUserStatsRequest{
		Name: user.GetUser().GetName(),
	})
	if err != nil {
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

	grpcCtx := s.prepareGrpcContext(ctx)
	name, err := s.searchMemoId(grpcCtx, memoId)
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to search memo id", "error", err)
		return err
	}

	resp, err := s.memoService.UpdateMemo(grpcCtx, &v1pb.UpdateMemoRequest{
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"pinned"}},
		Memo: &v1pb.Memo{
			Name:   name,
			Pinned: params.Pinned != nil && *params.Pinned,
		},
	})
	if err != nil {
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

	grpcCtx := s.prepareGrpcContext(ctx)
	name, err := s.searchMemoId(grpcCtx, memoId)
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
			name, err := s.searchResourceId(grpcCtx, resourceId)
			if err != nil {
				slog.ErrorContext(
					ctx.Request().Context(),
					"failed to search resource id",
					"error",
					err,
				)
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
			relatedName, err := s.searchMemoId(grpcCtx, *relation.RelatedMemoId)
			if err != nil {
				slog.ErrorContext(
					ctx.Request().Context(),
					"failed to search related memo id",
					"error",
					err,
				)
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

	resp, err := s.memoService.UpdateMemo(grpcCtx, req)
	if err != nil {
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

	grpcCtx := s.prepareGrpcContext(ctx)
	name, err := s.searchResourceId(grpcCtx, resourceId)
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

	resp, err := s.attachmentService.UpdateAttachment(grpcCtx, req)
	if err != nil {
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

	grpcCtx := s.prepareGrpcContext(ctx)
	resp, err := s.attachmentService.CreateAttachment(grpcCtx, &v1pb.CreateAttachmentRequest{
		Attachment: &v1pb.Attachment{
			Filename: file.Filename,
			Type:     mimeType,
			Content:  buf.Bytes(),
		},
	})
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to create resource", "error", err)
		return err
	}

	resource := s.convertResource(resp)
	return ctx.JSON(200, resource)
}

func (s *Server) StreamResource(ctx echo.Context) error {
	uid := ctx.Param("uid")

	// Call the gRPC service
	grpcCtx := s.prepareGrpcContext(ctx)
	body, err := s.attachmentService.GetAttachmentBinary(grpcCtx, &v1pb.GetAttachmentBinaryRequest{
		Name:      fmt.Sprintf("attachments/%s", uid),
		Thumbnail: ctx.QueryParam("thumbnail") == "1",
	})
	if err != nil {
		slog.ErrorContext(ctx.Request().Context(), "failed to get resource binary", "error", err)
		return err
	}

	return ctx.Stream(200, body.ContentType, bytes.NewReader(body.Data))
}

func NewServer(grpcAddr string) *Server {
	conn, err := grpc.NewClient(
		grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
	)
	if err != nil {
		panic(err)
	}

	return &Server{
		memoService:       v1pb.NewMemoServiceClient(conn),
		authService:       v1pb.NewAuthServiceClient(conn),
		instanceService:   v1pb.NewInstanceServiceClient(conn),
		userService:       v1pb.NewUserServiceClient(conn),
		attachmentService: v1pb.NewAttachmentServiceClient(conn),
		memoIdToName:      xsync.NewMapOf[int, string](),
		resourceIdToName:  xsync.NewMapOf[int, string](),
	}
}

func (s *Server) prepareGrpcContext(ctx echo.Context) context.Context {
	md := metadata.New(map[string]string{})
	if authHeader := ctx.Request().Header.Get("Authorization"); authHeader != "" {
		md.Set("Authorization", authHeader)
	}
	return metadata.NewOutgoingContext(ctx.Request().Context(), md)
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
	return &api.Memo{
		Id:           id,
		Content:      memo.Content,
		CreatedTs:    int(memo.CreateTime.AsTime().Unix()),
		CreatorId:    utils.IntPtr(int(hashToInt53(strings.TrimPrefix(memo.Creator, "users/")))),
		Pinned:       utils.BoolPtr(memo.Pinned),
		RowStatus:    &rowStatus,
		UpdatedTs:    utils.IntPtr(int(memo.UpdateTime.AsTime().Unix())),
		Visibility:   &visibility,
		ResourceList: &resources,
	}
}

func (s *Server) searchMemoId(ctx context.Context, memoId int) (string, error) {
	name, ok := s.memoIdToName.Load(memoId)
	if !ok {
		var currentPageToken string
		for {
			resp, err := s.memoService.ListMemos(ctx, &v1pb.ListMemosRequest{
				PageSize:  200,
				PageToken: currentPageToken,
			})
			if err != nil {
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

func (s *Server) searchResourceId(ctx context.Context, resourceId int) (string, error) {
	name, ok := s.resourceIdToName.Load(resourceId)
	if !ok {
		resp, err := s.attachmentService.ListAttachments(ctx, &v1pb.ListAttachmentsRequest{})
		if err != nil {
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

	}
	if name == "" {
		return "", errors.New("resource not found")
	}
	return name, nil
}

func marshalPageToken(pageToken *v1pb.PageToken) (string, error) {
	b, err := proto.Marshal(pageToken)
	if err != nil {
		return "", errors.Wrapf(err, "failed to marshal page token")
	}
	return base64.StdEncoding.EncodeToString(b), nil
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

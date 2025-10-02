package api

import (
	"context"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
)

func NewGetNoteListHandler(sensitiveDataClient sensitive.SensitiveDataServiceClient) func(ctx context.Context, authToken string, cryptoKey []byte) ([]*sensitive.NoteData, error) {
	return func(ctx context.Context, authToken string, cryptoKey []byte) ([]*sensitive.NoteData, error) {
		ctxWithToken := AddAuthToken(ctx, authToken)
		resp, err := sensitiveDataClient.GetTextDataList(ctxWithToken, &sensitive.GetTextDataListRequest{})
		if err != nil {
			return nil, err
		}

		for i, note := range resp.NoteData {
			decryptedNote, err := crypto.Decrypt(note.Data, cryptoKey)
			if err != nil {
				continue
			}
			resp.NoteData[i].Data = decryptedNote
		}

		return resp.NoteData, nil
	}
}

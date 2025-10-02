package api

import (
	"context"
	"errors"
	"github.com/ruslanDantsov/password-manager/client/mocks"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestNewGetNoteListHandler_Success(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	authToken := "test-auth-token"
	noteText := "My secret note content"
	cryptoKey := []byte("12345678901234567890123456789012")

	encryptedData, err := crypto.Encrypt([]byte(noteText), cryptoKey)
	assert.NoError(t, err)

	expectedNotes := []*sensitive.NoteData{
		{
			ServiceName: "Personal Notes",
			Data:        encryptedData,
		},
		{
			ServiceName: "Work Notes",
			Data:        encryptedData,
		},
	}

	mockResponse := &sensitive.GetTextDataListResponse{
		NoteData: expectedNotes,
	}

	mockClient.On("GetTextDataList", mock.Anything, &sensitive.GetTextDataListRequest{}).
		Return(mockResponse, nil)

	handler := NewGetNoteListHandler(mockClient)

	// Act
	notes, err := handler(context.Background(), authToken, cryptoKey)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, notes)
	assert.Len(t, notes, 2)

	assert.Equal(t, "Personal Notes", notes[0].ServiceName)
	assert.Equal(t, []byte(noteText), notes[0].Data)

	assert.Equal(t, "Work Notes", notes[1].ServiceName)
	assert.Equal(t, []byte(noteText), notes[1].Data)

	mockClient.AssertExpectations(t)
}

func TestNewGetNoteListHandler_ClientError(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	authToken := "test-auth-token"
	cryptoKey := []byte("12345678901234567890123456789012")
	expectedError := errors.New("unauthorized")

	mockClient.On("GetTextDataList", mock.Anything, &sensitive.GetTextDataListRequest{}).
		Return(nil, expectedError)

	handler := NewGetNoteListHandler(mockClient)

	// Act
	notes, err := handler(context.Background(), authToken, cryptoKey)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, notes)

	mockClient.AssertExpectations(t)
}

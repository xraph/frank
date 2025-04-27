package sso_test

import (
	"context"
	"testing"
	"time"

	"github.com/juicycleff/frank/ent/enttest"
	"github.com/juicycleff/frank/internal/auth/sso"
	"github.com/juicycleff/frank/pkg/logging"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntStateStore(t *testing.T) {
	// Create a test client using SQLite with an in-memory database
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer client.Close()

	// Create a logger for testing
	logger := logging.GetLogger()

	// Create the state store
	stateStore := sso.NewEntStateStore(client, logger)

	// Test context
	ctx := context.Background()

	// Test data
	testState := "test_state_123"
	testData := &sso.StateData{
		ProviderID:     "provider123",
		OrganizationID: "org456",
		RedirectURI:    "https://example.com/callback",
		Nonce:          "nonce789",
		Options: map[string]interface{}{
			"prompt": "login",
		},
	}

	// Test expiry
	testExpiry := 15 * time.Minute

	t.Run("Store and retrieve state", func(t *testing.T) {
		// Store the state
		err := stateStore.StoreState(ctx, testState, testData, testExpiry)
		require.NoError(t, err, "Failed to store state")

		// Retrieve the state
		retrievedData, err := stateStore.GetState(ctx, testState)
		require.NoError(t, err, "Failed to retrieve state")

		// Verify the data matches
		assert.Equal(t, testData.ProviderID, retrievedData.ProviderID)
		assert.Equal(t, testData.OrganizationID, retrievedData.OrganizationID)
		assert.Equal(t, testData.RedirectURI, retrievedData.RedirectURI)
		assert.Equal(t, testData.Nonce, retrievedData.Nonce)
		assert.Equal(t, "login", retrievedData.Options["prompt"])
	})

	t.Run("Update existing state", func(t *testing.T) {
		// Update the state with new data
		updatedData := &sso.StateData{
			ProviderID:     "provider123",
			OrganizationID: "org456",
			RedirectURI:    "https://example.com/updated-callback",
			Nonce:          "new-nonce-123",
			Options: map[string]interface{}{
				"prompt": "consent",
			},
		}

		// Store the updated state
		err := stateStore.StoreState(ctx, testState, updatedData, testExpiry)
		require.NoError(t, err, "Failed to update state")

		// Retrieve the state
		retrievedData, err := stateStore.GetState(ctx, testState)
		require.NoError(t, err, "Failed to retrieve updated state")

		// Verify the data was updated
		assert.Equal(t, updatedData.RedirectURI, retrievedData.RedirectURI)
		assert.Equal(t, updatedData.Nonce, retrievedData.Nonce)
		assert.Equal(t, "consent", retrievedData.Options["prompt"])
	})

	t.Run("Delete state", func(t *testing.T) {
		// Delete the state
		err := stateStore.DeleteState(ctx, testState)
		require.NoError(t, err, "Failed to delete state")

		// Try to retrieve the deleted state
		_, err = stateStore.GetState(ctx, testState)
		require.Error(t, err, "Expected error when retrieving deleted state")
	})

	t.Run("Retrieve non-existent state", func(t *testing.T) {
		// Try to retrieve a non-existent state
		_, err := stateStore.GetState(ctx, "non_existent_state")
		require.Error(t, err, "Expected error when retrieving non-existent state")
	})

	t.Run("Expired state", func(t *testing.T) {
		// Store state with very short expiry
		shortState := "short_lived_state"
		err := stateStore.StoreState(ctx, shortState, testData, 1*time.Millisecond)
		require.NoError(t, err, "Failed to store state with short expiry")

		// Wait for state to expire
		time.Sleep(10 * time.Millisecond)

		// Try to retrieve the expired state
		_, err = stateStore.GetState(ctx, shortState)
		require.Error(t, err, "Expected error when retrieving expired state")
	})

	t.Run("Cleanup expired states", func(t *testing.T) {
		// Store multiple states with varying expiry times
		for i := 0; i < 5; i++ {
			stateKey := "expire_test_state" + string(rune(i+'0'))
			// First 3 states expire immediately
			expiry := -1 * time.Minute
			if i >= 3 {
				// Last 2 states valid for 1 hour
				expiry = 1 * time.Hour
			}

			err := stateStore.StoreState(ctx, stateKey, testData, expiry)
			require.NoError(t, err, "Failed to store state "+stateKey)
		}

		// Run cleanup
		count, err := stateStore.CleanupExpiredStates(ctx)
		require.NoError(t, err, "Failed to cleanup expired states")

		// Should have cleaned up 3 states
		assert.Equal(t, 3, count, "Expected to clean up 3 expired states")
	})
}

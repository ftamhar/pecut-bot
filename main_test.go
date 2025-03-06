// main_test.go
package main

import (
	"fmt"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

func TestValidateActivity(t *testing.T) {

	// Test the validateActivity function
	meta, err := crawlling("https://www.strava.com/activities/13803183213?share_sig=8D81BB6D1741254389&utm_medium=social&utm_source=ios_share")

	if err != nil || meta == nil {
		t.Fatal(err)
	}

	fmt.Println("Activity: ", meta.ActivityName)
	fmt.Println("Date: ", meta.ActivityDate)
	fmt.Println("Distance: ", meta.Distance)
	fmt.Println("Time: ", meta.Time)
	fmt.Println("Elevation: ", meta.Elevation)

	assert.NoError(t, err)
	assert.NotNil(t, meta, "Expected activity to be valid")
}

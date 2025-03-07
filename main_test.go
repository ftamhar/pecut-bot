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
	meta, err := crawlling("https://www.strava.com/activities/13803183213")

	if err != nil || meta == nil {
		t.Fatal(err)
	}

	fmt.Println("Activity: ", meta.ActivityName)
	fmt.Println("Date: ", meta.ActivityDate)
	fmt.Println("Distance: ", meta.Distance)
	fmt.Println("Time: ", meta.Time)
	fmt.Println("Elevation: ", meta.Elevation)
	fmt.Println("--------------------------------")

	assert.NoError(t, err)
	assert.NotNil(t, meta, "Expected activity to be valid")

	// Test the validateActivity function
	meta, err = crawlling("https://www.strava.com/activities/13803686366")

	if err != nil || meta == nil {
		t.Fatal(err)
	}

	fmt.Println("Activity: ", meta.ActivityName)
	fmt.Println("Date: ", meta.ActivityDate)
	fmt.Println("Distance: ", meta.Distance)
	fmt.Println("Time: ", meta.Time)
	fmt.Println("Elevation: ", meta.Elevation)
	fmt.Println("--------------------------------")

	assert.NoError(t, err)
	assert.NotNil(t, meta, "Expected activity to be valid")

	// Test the validateActivity function
	meta, err = crawlling("https://www.strava.com/activities/13798765328")

	if err != nil || meta == nil {
		t.Fatal(err)
	}

	fmt.Println("Activity: ", meta.ActivityName)
	fmt.Println("Date: ", meta.ActivityDate)
	fmt.Println("Distance: ", meta.Distance)
	fmt.Println("Time: ", meta.Time)
	fmt.Println("Elevation: ", meta.Elevation)
	fmt.Println("--------------------------------")
	assert.NoError(t, err)
	assert.NotNil(t, meta, "Expected activity to be valid")
}

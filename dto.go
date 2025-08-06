package main

type Activity struct {
	ActivityDate  string
	ActivityName  string
	DistanceMeter float64
	Time          string
	Elevation     float64
	Pace          string
	ImageUrl      string

	Status    int
	TimeZone  string
	SportType string
}

type ResponseJson struct {
	Props struct {
		PageProps struct {
			Activity struct {
				ActivityKind struct {
					SportType string `json:"sportType"`
				} `json:"activityKind"`
				MapImages []struct {
					URL string `json:"url"`
				} `json:"mapImages"`
				Visibility string `json:"visibility"`
				Athlete    struct {
					ID        string `json:"id"`
					FirstName string `json:"firstName"`
					LastName  string `json:"lastName"`
				} `json:"athlete"`
				CommentCount int    `json:"commentCount"`
				Description  string `json:"description"`
				Name         string `json:"name"`
				Scalars      struct {
					Distance      float64 `json:"distance"`
					ElevationGain float64 `json:"elevationGain"`
					MovingTime    int     `json:"movingTime"`
				} `json:"scalars"`
				StartLocal string `json:"startLocal"`
				Streams    struct {
					Location []struct {
						Lat float64 `json:"lat"`
						Lng float64 `json:"lng"`
					} `json:"location"`
				} `json:"streams"`
			} `json:"activity"`
		} `json:"pageProps"`
	} `json:"props"`
}

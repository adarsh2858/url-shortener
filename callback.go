package url_shortener

import "fmt"

func process(data string, callback_func func(url string) string) string {
	for _, partial_url := range data {
		fmt.Print(partial_url)
	}

	return callback_func(data)
}

func callback_func(url string) string {
	return "https://" + url
}
